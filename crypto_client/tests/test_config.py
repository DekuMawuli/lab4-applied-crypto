import json

import pytest

from crypto_client.config import load_config


def test_load_config_reads_server_ip_port_username(tmp_path):
    path = tmp_path / "config.local.json"
    path.write_text(json.dumps({"server_ip": "203.0.113.5", "port": 8080, "username": "student01"}))

    config = load_config(path)

    assert config == {"server_ip": "203.0.113.5", "port": 8080, "username": "student01"}


def test_load_config_missing_file_returns_empty_dict(tmp_path):
    missing = tmp_path / "does_not_exist.json"

    assert load_config(missing) == {}


def test_load_config_missing_file_falls_back_to_given_path(tmp_path):
    fallback = tmp_path / "config.example.json"
    fallback.write_text(json.dumps({"server_ip": "0.0.0.0", "port": 8080, "username": "your_username"}))
    missing = tmp_path / "config.local.json"

    config = load_config(missing, fallback=fallback)

    assert config["username"] == "your_username"
