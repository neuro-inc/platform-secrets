import pytest
import trafaret as t

from platform_secrets.validators import (
    SECRET_DUMMY_KEY,
    secret_request_validator,
    secret_response_validator,
)


@pytest.mark.parametrize(
    "key",
    ["", "?", "\n", "\t", " ", ".", "..", "...", "..-", "/", "\\", SECRET_DUMMY_KEY],
)
def test_secret_request_validator__invalid_key(key: str) -> None:
    validator = secret_request_validator
    payload = {"key": key, "value": "vvvv", "project_name": "test-project"}
    with pytest.raises(t.DataError):
        validator.check(payload)


def test_secret_request_validator__invalid_key_too_long() -> None:
    key = "a" * 254
    validator = secret_request_validator
    payload = {"key": key, "value": "vvvv", "project_name": "test-project"}
    with pytest.raises(t.DataError):
        validator.check(payload)


@pytest.mark.parametrize("key", ["a", ".-", "-", "_", "0", "A"])
def test_secret_request_validator__valid_key(key: str) -> None:
    validator = secret_request_validator
    payload = {"key": key, "value": "vvvv", "project_name": "test-project"}
    result = validator.check(payload)
    assert result == payload


def test_secret_request_validator__valid_key_max_len() -> None:
    key = "a" * 253
    validator = secret_request_validator
    payload = {"key": key, "value": "vvvv", "project_name": "test-project"}
    result = validator.check(payload)
    assert result == payload


def test_secret_request_validator__invalid_value_base64() -> None:
    validator = secret_request_validator
    payload = {"key": "testkey", "value": "vvvvv", "project_name": "test-project"}
    with pytest.raises(t.DataError, match="Invalid base64-encoded string"):
        validator.check(payload)


def test_secret_request_validator__valid_value_max_len() -> None:
    value = "v" * 1024 * 1024
    validator = secret_request_validator
    payload = {"key": "testkey", "value": value, "project_name": "test-project"}
    result = validator.check(payload)
    assert result == payload


def test_secret_request_validator__invalid_value_too_long() -> None:
    value = "v" * (1024 * 1024 + 1)
    validator = secret_request_validator
    payload = {"key": "testkey", "value": value, "project_name": "test-project"}
    with pytest.raises(t.DataError):
        validator.check(payload)


def test_secret_request_validator__without_project() -> None:
    validator = secret_request_validator
    payload = {"key": "testkey", "value": "vvvv"}
    result = validator.check(payload)
    assert result == payload


def test_secret_response_validator__long_key() -> None:
    validator = secret_response_validator
    payload = {
        "key": "k" * 255,
        "owner": "test",
        "org_name": None,
        "project_name": "test-project",
    }
    result = validator.check(payload)
    assert result == payload


def test_secret_response_validator__with_org() -> None:
    validator = secret_response_validator
    payload = {
        "key": "key",
        "owner": "test",
        "org_name": "test-org",
        "project_name": "test-project",
    }
    result = validator.check(payload)
    assert result == payload
