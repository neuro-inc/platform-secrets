import pytest
import trafaret as t

from platform_secrets.validators import (
    SECRET_DUMMY_KEY,
    secret_request_validator,
    secret_response_validator,
    secret_with_value_response_validator,
)


@pytest.fixture
def org_name() -> str:
    return "test-org"


@pytest.fixture
def project_name() -> str:
    return "test-project"


@pytest.mark.parametrize(
    "key",
    ["", "?", "\n", "\t", " ", ".", "..", "...", "..-", "/", "\\", SECRET_DUMMY_KEY],
)
def test_secret_request_validator__invalid_key(
    key: str,
    org_name: str,
    project_name: str,
) -> None:
    validator = secret_request_validator
    payload = {
        "key": key,
        "value": "vvvv",
        "org_name": org_name,
        "project_name": project_name,
    }
    with pytest.raises(t.DataError):
        validator.check(payload)


def test_secret_request_validator__invalid_key_too_long(
    org_name: str,
    project_name: str,
) -> None:
    key = "a" * 254
    validator = secret_request_validator
    payload = {
        "key": key,
        "value": "vvvv",
        "org_name": org_name,
        "project_name": project_name,
    }
    with pytest.raises(t.DataError):
        validator.check(payload)


@pytest.mark.parametrize("key", ["a", ".-", "-", "_", "0", "A"])
def test_secret_request_validator__valid_key(
    key: str,
    org_name: str,
    project_name: str,
) -> None:
    validator = secret_request_validator
    payload = {
        "key": key,
        "value": "vvvv",
        "org_name": org_name,
        "project_name": project_name,
    }
    result = validator.check(payload)
    assert result == payload


def test_secret_request_validator__valid_key_max_len(
    org_name: str,
    project_name: str,
) -> None:
    key = "a" * 253
    validator = secret_request_validator
    payload = {
        "key": key,
        "value": "vvvv",
        "org_name": org_name,
        "project_name": project_name,
    }
    result = validator.check(payload)
    assert result == payload


def test_secret_request_validator__invalid_value_base64(
    org_name: str,
    project_name: str,
) -> None:
    validator = secret_request_validator
    payload = {
        "key": "testkey",
        "value": "vvvvv",
        "org_name": org_name,
        "project_name": project_name,
    }
    with pytest.raises(t.DataError, match="Invalid base64-encoded string"):
        validator.check(payload)


def test_secret_request_validator__valid_value_max_len(
    org_name: str,
    project_name: str,
) -> None:
    value = "v" * 1024 * 1024
    validator = secret_request_validator
    payload = {
        "key": "testkey",
        "value": value,
        "org_name": org_name,
        "project_name": project_name,
    }
    result = validator.check(payload)
    assert result == payload


def test_secret_request_validator__invalid_value_too_long(
    org_name: str,
    project_name: str,
) -> None:
    value = "v" * (1024 * 1024 + 1)
    validator = secret_request_validator
    payload = {
        "key": "testkey",
        "value": value,
        "org_name": org_name,
        "project_name": project_name,
    }
    with pytest.raises(t.DataError):
        validator.check(payload)


def test_secret_response_validator__long_key(
    org_name: str,
    project_name: str,
) -> None:
    validator = secret_response_validator
    payload = {
        "key": "k" * 255,
        "owner": "test",
        "org_name": org_name,
        "project_name": project_name,
    }
    result = validator.check(payload)
    assert result == payload


def test_secret_response_validator__with_org(
    org_name: str,
    project_name: str,
) -> None:
    validator = secret_response_validator
    payload = {
        "key": "key",
        "owner": "test",
        "org_name": org_name,
        "project_name": project_name,
    }
    result = validator.check(payload)
    assert result == payload


def test_secret_with_value_response_validator__valid(
    org_name: str,
    project_name: str,
) -> None:
    validator = secret_with_value_response_validator
    payload = {
        "key": "test-key",
        "value": "test-value",
        "owner": "test-owner",
        "org_name": org_name,
        "project_name": project_name,
    }
    result = validator.check(payload)
    assert result == payload


def test_secret_with_value_response_validator__missing_value(
    org_name: str,
    project_name: str,
) -> None:
    validator = secret_with_value_response_validator
    payload = {
        "key": "test-key",
        "owner": "test-owner",
        "org_name": org_name,
        "project_name": project_name,
    }
    with pytest.raises(t.DataError, match="is required"):
        validator.check(payload)
