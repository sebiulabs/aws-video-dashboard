"""Tests for cost_dashboard.py — pure logic and mocked Cost Explorer / Budgets calls."""

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

import cost_dashboard


# ═════════════════════════════════════════════════════════════════════════════
# PURE LOGIC
# ═════════════════════════════════════════════════════════════════════════════


class TestSanitizeError:
    def test_strips_credentials(self):
        msg = "Error for AKIAIOSFODNN7EXAMPLE in account 123456789012"
        result = cost_dashboard._sanitize_error(msg)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "123456789012" not in result
        assert "****" in result


# ═════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════════════════════════


def _make_client_error(code="AccessDenied", message="Access Denied"):
    return ClientError(
        {"Error": {"Code": code, "Message": message}},
        "TestOperation",
    )


# ═════════════════════════════════════════════════════════════════════════════
# DAILY COSTS
# ═════════════════════════════════════════════════════════════════════════════


class TestGetDailyCosts:
    @patch("cost_dashboard.boto3.Session")
    def test_success(self, mock_session_cls, sample_config):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        mock_client.get_cost_and_usage.return_value = {
            "ResultsByTime": [
                {
                    "TimePeriod": {"Start": "2024-01-15", "End": "2024-01-16"},
                    "Groups": [
                        {
                            "Keys": ["Amazon EC2"],
                            "Metrics": {"UnblendedCost": {"Amount": "10.50"}},
                        },
                        {
                            "Keys": ["Amazon S3"],
                            "Metrics": {"UnblendedCost": {"Amount": "3.25"}},
                        },
                    ],
                },
                {
                    "TimePeriod": {"Start": "2024-01-16", "End": "2024-01-17"},
                    "Groups": [
                        {
                            "Keys": ["Amazon EC2"],
                            "Metrics": {"UnblendedCost": {"Amount": "12.00"}},
                        },
                    ],
                },
            ]
        }

        result = cost_dashboard.get_daily_costs(sample_config, days=2)
        assert len(result["days"]) == 2
        assert result["days"][0]["date"] == "2024-01-15"
        assert result["days"][0]["services"]["Amazon EC2"] == 10.50
        assert result["total"] > 0

    @patch("cost_dashboard.boto3.Session")
    def test_enforces_max_90_days(self, mock_session_cls, sample_config):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_client.get_cost_and_usage.return_value = {"ResultsByTime": []}

        cost_dashboard.get_daily_costs(sample_config, days=200)

        # Verify the call was made — the function clamps to 90 days internally
        call_args = mock_client.get_cost_and_usage.call_args
        start = call_args[1]["TimePeriod"]["Start"] if call_args[1] else call_args.kwargs["TimePeriod"]["Start"]
        end = call_args[1]["TimePeriod"]["End"] if call_args[1] else call_args.kwargs["TimePeriod"]["End"]
        from datetime import date
        start_date = date.fromisoformat(start)
        end_date = date.fromisoformat(end)
        delta = (end_date - start_date).days
        assert delta <= 90

    @patch("cost_dashboard.boto3.Session")
    def test_client_error_returns_empty(self, mock_session_cls, sample_config):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_client.get_cost_and_usage.side_effect = _make_client_error()

        result = cost_dashboard.get_daily_costs(sample_config)
        assert result["days"] == []
        assert result["total"] == 0.0


# ═════════════════════════════════════════════════════════════════════════════
# MONTHLY SUMMARY
# ═════════════════════════════════════════════════════════════════════════════


class TestGetMonthlySummary:
    @patch("cost_dashboard.boto3.Session")
    def test_success_with_multiple_months(self, mock_session_cls, sample_config):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        mock_client.get_cost_and_usage.return_value = {
            "ResultsByTime": [
                {
                    "TimePeriod": {"Start": "2024-01-01", "End": "2024-02-01"},
                    "Total": {"UnblendedCost": {"Amount": "400.00"}},
                },
                {
                    "TimePeriod": {"Start": "2024-02-01", "End": "2024-03-01"},
                    "Total": {"UnblendedCost": {"Amount": "500.00"}},
                },
                {
                    "TimePeriod": {"Start": "2024-03-01", "End": "2024-04-01"},
                    "Total": {"UnblendedCost": {"Amount": "450.00"}},
                },
            ]
        }

        result = cost_dashboard.get_monthly_summary(sample_config, months=3)
        assert len(result["months"]) == 3
        assert result["months"][0]["month"] == "2024-01"
        assert result["months"][0]["total"] == 400.00
        assert result["total"] == 1350.00

    @patch("cost_dashboard.boto3.Session")
    def test_calculates_month_over_month_change(self, mock_session_cls, sample_config):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        mock_client.get_cost_and_usage.return_value = {
            "ResultsByTime": [
                {
                    "TimePeriod": {"Start": "2024-01-01", "End": "2024-02-01"},
                    "Total": {"UnblendedCost": {"Amount": "100.00"}},
                },
                {
                    "TimePeriod": {"Start": "2024-02-01", "End": "2024-03-01"},
                    "Total": {"UnblendedCost": {"Amount": "120.00"}},
                },
            ]
        }

        result = cost_dashboard.get_monthly_summary(sample_config, months=2)
        # First month has no change_pct
        assert "change_pct" not in result["months"][0]
        # Second month: (120-100)/100 * 100 = 20.0%
        assert result["months"][1]["change_pct"] == 20.0

    @patch("cost_dashboard.boto3.Session")
    def test_empty_response(self, mock_session_cls, sample_config):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_client.get_cost_and_usage.return_value = {"ResultsByTime": []}

        result = cost_dashboard.get_monthly_summary(sample_config)
        assert result["months"] == []
        assert result["total"] == 0.0


# ═════════════════════════════════════════════════════════════════════════════
# SERVICE BREAKDOWN
# ═════════════════════════════════════════════════════════════════════════════


class TestGetServiceBreakdown:
    @patch("cost_dashboard.boto3.Session")
    def test_success(self, mock_session_cls, sample_config):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        mock_client.get_cost_and_usage.return_value = {
            "ResultsByTime": [
                {
                    "TimePeriod": {"Start": "2024-01-15"},
                    "Groups": [
                        {"Keys": ["Amazon EC2"], "Metrics": {"UnblendedCost": {"Amount": "100.00"}}},
                        {"Keys": ["Amazon S3"], "Metrics": {"UnblendedCost": {"Amount": "50.00"}}},
                        {"Keys": ["AWS Lambda"], "Metrics": {"UnblendedCost": {"Amount": "25.00"}}},
                    ],
                }
            ]
        }

        result = cost_dashboard.get_service_breakdown(sample_config, days=30)
        assert result["total"] == 175.00
        assert result["period_days"] == 30
        assert len(result["services"]) == 3

    @patch("cost_dashboard.boto3.Session")
    def test_sorts_by_cost_descending(self, mock_session_cls, sample_config):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        mock_client.get_cost_and_usage.return_value = {
            "ResultsByTime": [
                {
                    "TimePeriod": {"Start": "2024-01-15"},
                    "Groups": [
                        {"Keys": ["AWS Lambda"], "Metrics": {"UnblendedCost": {"Amount": "10.00"}}},
                        {"Keys": ["Amazon EC2"], "Metrics": {"UnblendedCost": {"Amount": "100.00"}}},
                        {"Keys": ["Amazon S3"], "Metrics": {"UnblendedCost": {"Amount": "50.00"}}},
                    ],
                }
            ]
        }

        result = cost_dashboard.get_service_breakdown(sample_config)
        costs = [s["cost"] for s in result["services"]]
        assert costs == sorted(costs, reverse=True)
        assert result["services"][0]["name"] == "Amazon EC2"


# ═════════════════════════════════════════════════════════════════════════════
# BUDGET STATUS
# ═════════════════════════════════════════════════════════════════════════════


class TestGetBudgetStatus:
    @patch("cost_dashboard.boto3.Session")
    def test_success(self, mock_session_cls, sample_config):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        mock_budgets = MagicMock()
        mock_budgets.describe_budgets.return_value = {
            "Budgets": [
                {
                    "BudgetName": "Monthly Budget",
                    "BudgetLimit": {"Amount": "1000.00"},
                    "CalculatedSpend": {
                        "ActualSpend": {"Amount": "450.00"},
                        "ForecastedSpend": {"Amount": "900.00"},
                    },
                }
            ]
        }

        def client_factory(service, **kwargs):
            if service == "sts":
                return mock_sts
            return mock_budgets

        mock_session.client.side_effect = client_factory

        result = cost_dashboard.get_budget_status(sample_config)
        assert len(result["budgets"]) == 1
        assert result["budgets"][0]["name"] == "Monthly Budget"
        assert result["budgets"][0]["limit"] == 1000.00
        assert result["budgets"][0]["actual"] == 450.00
        assert result["budgets"][0]["pct_used"] == 45.0

    @patch("cost_dashboard.boto3.Session")
    def test_over_budget(self, mock_session_cls, sample_config):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        mock_budgets = MagicMock()
        mock_budgets.describe_budgets.return_value = {
            "Budgets": [
                {
                    "BudgetName": "Overrun Budget",
                    "BudgetLimit": {"Amount": "500.00"},
                    "CalculatedSpend": {
                        "ActualSpend": {"Amount": "750.00"},
                        "ForecastedSpend": {"Amount": "1200.00"},
                    },
                }
            ]
        }

        def client_factory(service, **kwargs):
            if service == "sts":
                return mock_sts
            return mock_budgets

        mock_session.client.side_effect = client_factory

        result = cost_dashboard.get_budget_status(sample_config)
        assert result["budgets"][0]["pct_used"] == 150.0
        assert result["budgets"][0]["actual"] == 750.00
        assert result["budgets"][0]["forecasted"] == 1200.00

    @patch("cost_dashboard.boto3.Session")
    def test_no_budgets_client_error(self, mock_session_cls, sample_config):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        mock_budgets = MagicMock()
        mock_budgets.describe_budgets.side_effect = ClientError(
            {"Error": {"Code": "NotFoundException", "Message": "No budgets"}},
            "DescribeBudgets",
        )

        def client_factory(service, **kwargs):
            if service == "sts":
                return mock_sts
            return mock_budgets

        mock_session.client.side_effect = client_factory

        result = cost_dashboard.get_budget_status(sample_config)
        assert result["budgets"] == []
