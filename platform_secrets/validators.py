import base64

import trafaret as t


SECRET_KEY_PATTERN = r"\A(?!\.\Z|\.\.)[a-zA-Z0-9_\-\.]*\Z"


def check_base64(value: str) -> str:
    try:
        base64.b64decode(value)
    except Exception as exc:
        raise t.DataError(str(exc))
    return value


secret_key_validator = t.String(min_length=1, max_length=253) & t.Regexp(
    SECRET_KEY_PATTERN
)
secret_value_validator = t.String(max_length=1024 * 1024) >> check_base64
secret_request_validator = t.Dict(
    {"key": secret_key_validator, "value": secret_value_validator}
)
secret_response_validator = t.Dict({"key": t.String})
