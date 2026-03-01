"""
AWS Cost Explorer Dashboard
============================
Provides cost analysis functions for the AWS Video Engineering Dashboard:
  - Daily cost breakdown by service over a configurable lookback window
  - Monthly cost summaries with month-over-month change percentages
  - Per-service cost breakdown with percentage-of-total calculations
  - AWS Budgets status including actual spend vs. limits and forecasts

All functions use the same config["aws"] credential pattern as video_monitor.py
and target the us-east-1 region, which is required by the Cost Explorer API.
"""

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def _sanitize_error(e):
    msg = str(e)
    msg = re.sub(r"(AKIA|ASIA|AIDA|AROA|AIPA)[A-Z0-9]{12,}", "****", msg)
    msg = re.sub(r"\b\d{12}\b", "****", msg)
    msg = re.sub(r"arn:aws:[a-zA-Z0-9_-]+:[a-z0-9-]*:\d{12}:[^\s,\"']+", "arn:aws:****", msg)
    return msg


# ═════════════════════════════════════════════════════════════════════════════
# SESSION HELPER
# ═════════════════════════════════════════════════════════════════════════════

def _get_session(config: dict, region: str = "us-east-1") -> boto3.Session:
    """
    Create a boto3 Session using credentials from config["aws"].

    Cost Explorer and Budgets APIs are only available in us-east-1,
    so the region defaults to us-east-1.
    """
    kwargs = {"region_name": region}
    if config["aws"].get("access_key_id") and config["aws"].get("secret_access_key"):
        kwargs["aws_access_key_id"] = config["aws"]["access_key_id"]
        kwargs["aws_secret_access_key"] = config["aws"]["secret_access_key"]
    return boto3.Session(**kwargs)


# ═════════════════════════════════════════════════════════════════════════════
# DAILY COSTS
# ═════════════════════════════════════════════════════════════════════════════

def get_daily_costs(config: dict, days: int = 30) -> dict:
    """
    Get daily cost breakdown by service for the last N days.

    Uses the Cost Explorer get_cost_and_usage API with DAILY granularity,
    grouped by SERVICE.

    Args:
        config: Application config dict with config["aws"] credentials.
        days:   Number of days to look back (max 90).

    Returns:
        {
            "days": [
                {
                    "date": "2024-01-15",
                    "total": 12.50,
                    "services": {"Amazon EC2": 5.00, "Amazon S3": 3.50, ...}
                },
                ...
            ],
            "total": 375.00
        }
    """
    days = min(days, 90)
    end_date = datetime.now(timezone.utc).date()
    start_date = end_date - timedelta(days=days)

    session = _get_session(config)
    client = session.client("ce")

    result_days = []
    grand_total = 0.0

    try:
        response = client.get_cost_and_usage(
            TimePeriod={
                "Start": start_date.isoformat(),
                "End": end_date.isoformat(),
            },
            Granularity="DAILY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )

        for result in response.get("ResultsByTime", []):
            date_str = result["TimePeriod"]["Start"]
            services = {}
            day_total = 0.0

            for group in result.get("Groups", []):
                service_name = group["Keys"][0]
                amount = round(float(group["Metrics"]["UnblendedCost"]["Amount"]), 2)
                if amount != 0.0:
                    services[service_name] = amount
                    day_total += amount

            day_total = round(day_total, 2)
            grand_total += day_total

            result_days.append({
                "date": date_str,
                "total": day_total,
                "services": services,
            })

    except ClientError as e:
        logger.warning(f"Cost Explorer daily costs failed: {_sanitize_error(e)}")
    except Exception as e:
        logger.warning(f"Unexpected error fetching daily costs: {_sanitize_error(e)}")

    return {
        "days": result_days,
        "total": round(grand_total, 2),
    }


# ═════════════════════════════════════════════════════════════════════════════
# MONTHLY SUMMARY
# ═════════════════════════════════════════════════════════════════════════════

def get_monthly_summary(config: dict, months: int = 6) -> dict:
    """
    Get monthly cost totals with month-over-month change percentages.

    Uses the Cost Explorer get_cost_and_usage API with MONTHLY granularity.
    The first month in the result has no change_pct since there is no
    prior month to compare against.

    Args:
        config: Application config dict with config["aws"] credentials.
        months: Number of months to look back (max 12).

    Returns:
        {
            "months": [
                {"month": "2024-01", "total": 450.00, "change_pct": 5.2},
                ...
            ],
            "total": 2700.00
        }
    """
    months = min(months, 12)
    today = datetime.now(timezone.utc).date()
    # Start from the 1st of (months) months ago
    # Go back enough months from the start of the current month
    end_date = today.replace(day=1) + timedelta(days=32)
    end_date = end_date.replace(day=1)  # 1st of next month
    start_date = today.replace(day=1)
    for _ in range(months):
        start_date = (start_date - timedelta(days=1)).replace(day=1)

    session = _get_session(config)
    client = session.client("ce")

    result_months = []
    grand_total = 0.0

    try:
        response = client.get_cost_and_usage(
            TimePeriod={
                "Start": start_date.isoformat(),
                "End": end_date.isoformat(),
            },
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
        )

        prev_total = None
        for result in response.get("ResultsByTime", []):
            period_start = result["TimePeriod"]["Start"]
            month_str = period_start[:7]  # "YYYY-MM"
            month_total = round(
                float(result["Total"]["UnblendedCost"]["Amount"]), 2
            )
            grand_total += month_total

            entry = {
                "month": month_str,
                "total": month_total,
            }

            if prev_total is not None and prev_total != 0.0:
                change_pct = round(
                    ((month_total - prev_total) / prev_total) * 100, 1
                )
                entry["change_pct"] = change_pct

            result_months.append(entry)
            prev_total = month_total

        # Mark the last month as partial if it's the current month
        for entry in result_months:
            entry_date = datetime.strptime(entry["month"], "%Y-%m").date()
            if entry_date.year == today.year and entry_date.month == today.month:
                entry["partial"] = True

    except ClientError as e:
        logger.warning(f"Cost Explorer monthly summary failed: {_sanitize_error(e)}")
    except Exception as e:
        logger.warning(f"Unexpected error fetching monthly summary: {_sanitize_error(e)}")

    return {
        "months": result_months,
        "total": round(grand_total, 2),
    }


# ═════════════════════════════════════════════════════════════════════════════
# SERVICE BREAKDOWN
# ═════════════════════════════════════════════════════════════════════════════

def get_service_breakdown(config: dict, days: int = 30) -> dict:
    """
    Get per-service cost breakdown for a given period.

    Uses the Cost Explorer get_cost_and_usage API with DAILY granularity
    grouped by SERVICE, then aggregates totals per service in code.
    Results are sorted by cost descending.

    Args:
        config: Application config dict with config["aws"] credentials.
        days:   Number of days to cover (max 90).

    Returns:
        {
            "services": [
                {"name": "Amazon EC2", "cost": 150.00, "pct": 33.3},
                ...
            ],
            "total": 450.00,
            "period_days": 30
        }
    """
    days = min(days, 90)
    end_date = datetime.now(timezone.utc).date()
    start_date = end_date - timedelta(days=days)

    session = _get_session(config)
    client = session.client("ce")

    service_totals = {}
    grand_total = 0.0

    try:
        response = client.get_cost_and_usage(
            TimePeriod={
                "Start": start_date.isoformat(),
                "End": end_date.isoformat(),
            },
            Granularity="DAILY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )

        for result in response.get("ResultsByTime", []):
            for group in result.get("Groups", []):
                service_name = group["Keys"][0]
                amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
                service_totals[service_name] = service_totals.get(service_name, 0.0) + amount
                grand_total += amount

    except ClientError as e:
        logger.warning(f"Cost Explorer service breakdown failed: {_sanitize_error(e)}")
    except Exception as e:
        logger.warning(f"Unexpected error fetching service breakdown: {_sanitize_error(e)}")

    grand_total = round(grand_total, 2)

    # Build sorted list with percentage of total
    services = []
    for name, cost in sorted(service_totals.items(), key=lambda x: x[1], reverse=True):
        rounded_cost = round(cost, 2)
        if rounded_cost == 0.0:
            continue
        pct = round((cost / grand_total) * 100, 1) if grand_total > 0 else 0.0
        services.append({
            "name": name,
            "cost": rounded_cost,
            "pct": pct,
        })

    return {
        "services": services,
        "total": grand_total,
        "period_days": days,
    }


# ═════════════════════════════════════════════════════════════════════════════
# BUDGET STATUS
# ═════════════════════════════════════════════════════════════════════════════

def get_budget_status(config: dict) -> dict:
    """
    Get AWS Budgets status including spend vs. limit and forecasted spend.

    Uses the AWS Budgets describe_budgets API. Requires the AWS account ID,
    which is obtained via STS get_caller_identity.

    Args:
        config: Application config dict with config["aws"] credentials.

    Returns:
        {
            "budgets": [
                {
                    "name": "Monthly Budget",
                    "limit": 1000.00,
                    "actual": 450.00,
                    "forecasted": 900.00,
                    "pct_used": 45.0
                },
                ...
            ]
        }
    """
    session = _get_session(config)
    result_budgets = []

    try:
        # Get the AWS account ID via STS
        sts_client = session.client("sts")
        account_id = sts_client.get_caller_identity()["Account"]

        budgets_client = session.client("budgets")

        try:
            response = budgets_client.describe_budgets(AccountId=account_id)

            for budget in response.get("Budgets", []):
                name = budget.get("BudgetName", "Unknown")

                limit_amount = round(
                    float(budget.get("BudgetLimit", {}).get("Amount", 0)), 2
                )

                actual_spend = round(
                    float(
                        budget.get("CalculatedSpend", {})
                        .get("ActualSpend", {})
                        .get("Amount", 0)
                    ),
                    2,
                )

                forecasted_spend = round(
                    float(
                        budget.get("CalculatedSpend", {})
                        .get("ForecastedSpend", {})
                        .get("Amount", 0)
                    ),
                    2,
                )

                pct_used = (
                    round((actual_spend / limit_amount) * 100, 1)
                    if limit_amount > 0
                    else 0.0
                )

                result_budgets.append({
                    "name": name,
                    "limit": limit_amount,
                    "actual": actual_spend,
                    "forecasted": forecasted_spend,
                    "pct_used": pct_used,
                })

        except ClientError as e:
            # No budgets configured or access denied
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NotFoundException":
                logger.info("No AWS Budgets configured for this account.")
            else:
                logger.warning(f"AWS Budgets describe_budgets failed: {_sanitize_error(e)}")

    except ClientError as e:
        logger.warning(f"Failed to get account ID via STS: {_sanitize_error(e)}")
    except Exception as e:
        logger.warning(f"Unexpected error fetching budget status: {_sanitize_error(e)}")

    return {
        "budgets": result_budgets,
    }
