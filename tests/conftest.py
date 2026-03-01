import copy
import json
import os
import sys
import pytest

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

@pytest.fixture
def tmp_config(tmp_path, monkeypatch):
    """Temp config file, patches config_manager.CONFIG_PATH."""
    config_file = str(tmp_path / "config.json")
    monkeypatch.setattr("config_manager.CONFIG_PATH", config_file)
    return config_file

@pytest.fixture
def tmp_history_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "history.db")
    monkeypatch.setattr("history_db.DB_PATH", db_path)
    return db_path

@pytest.fixture
def tmp_incidents_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "incidents.db")
    monkeypatch.setattr("incident_manager.DB_PATH", db_path)
    return db_path

@pytest.fixture
def tmp_schedules_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "schedules.db")
    monkeypatch.setattr("schedule_manager.DB_PATH", db_path)
    return db_path

@pytest.fixture
def tmp_users_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "users.db")
    monkeypatch.setattr("user_manager.DB_PATH", db_path)
    return db_path

@pytest.fixture
def tmp_remediation_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "remediation.db")
    monkeypatch.setattr("remediation.DB_PATH", db_path)
    return db_path

@pytest.fixture
def tmp_endpoints_file(tmp_path, monkeypatch):
    ep_path = str(tmp_path / "easy_monitor.json")
    monkeypatch.setattr("easy_monitor.ENDPOINTS_PATH", ep_path)
    return ep_path

@pytest.fixture
def sample_config():
    from config_manager import DEFAULT_CONFIG
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["aws"]["access_key_id"] = "AKIAIOSFODNN7EXAMPLE"
    cfg["aws"]["secret_access_key"] = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    cfg["aws"]["region"] = "eu-west-2"
    cfg["aws"]["regions"] = ["eu-west-2"]
    return cfg

@pytest.fixture
def flask_client(tmp_path, monkeypatch):
    """Fully isolated Flask test client."""
    monkeypatch.setattr("config_manager.CONFIG_PATH", str(tmp_path / "config.json"))
    monkeypatch.setattr("history_db.DB_PATH", str(tmp_path / "history.db"))
    monkeypatch.setattr("incident_manager.DB_PATH", str(tmp_path / "incidents.db"))
    monkeypatch.setattr("schedule_manager.DB_PATH", str(tmp_path / "schedules.db"))
    monkeypatch.setattr("user_manager.DB_PATH", str(tmp_path / "users.db"))
    monkeypatch.setattr("remediation.DB_PATH", str(tmp_path / "remediation.db"))
    from app import app
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret"
    with app.test_client() as client:
        yield client
