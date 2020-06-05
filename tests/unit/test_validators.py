import pytest
import trafaret as t

from platform_secrets.validators import (
    secret_request_validator,
    secret_response_validator,
)


@pytest.mark.parametrize(
    "key", ["", "?", "\n", "\t", " ", ".", "..", "...", "..-", "/", "\\"]
)
def test_secret_request_validator__invalid_key(key: str) -> None:
    validator = secret_request_validator
    payload = {"key": key, "value": "vvvv"}
    with pytest.raises(t.DataError):
        validator.check(payload)


def test_secret_request_validator__invalid_key_too_long() -> None:
    key = "a" * 254
    validator = secret_request_validator
    payload = {"key": key, "value": "vvvv"}
    with pytest.raises(t.DataError):
        validator.check(payload)


@pytest.mark.parametrize("key", ["a", ".-", "-", "_", "0", "A"])
def test_secret_request_validator__valid_key(key: str) -> None:
    validator = secret_request_validator
    payload = {"key": key, "value": "vvvv"}
    result = validator.check(payload)
    assert result == payload


def test_secret_request_validator__valid_key_max_len() -> None:
    key = "a" * 253
    validator = secret_request_validator
    payload = {"key": key, "value": "vvvv"}
    result = validator.check(payload)
    assert result == payload


def test_secret_request_validator__invalid_value_base64() -> None:
    validator = secret_request_validator
    payload = {"key": "testkey", "value": "vvvvv"}
    with pytest.raises(t.DataError, match="Invalid base64-encoded string"):
        validator.check(payload)


def test_secret_request_validator__valid_value_max_len() -> None:
    value = "v" * 1024 * 1024
    validator = secret_request_validator
    payload = {"key": "testkey", "value": value}
    result = validator.check(payload)
    assert result == payload


def test_secret_request_validator__invalid_value_too_long() -> None:
    value = "v" * (1024 * 1024 + 1)
    validator = secret_request_validator
    payload = {"key": "testkey", "value": value}
    with pytest.raises(t.DataError):
        validator.check(payload)


def test_secret_response_validator__long_key() -> None:
    validator = secret_response_validator
    payload = {"key": "k" * 255}
    result = validator.check(payload)
    assert result == payload
