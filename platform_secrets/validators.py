import base64

import trafaret as t

from .kube_client import SECRET_DUMMY_KEY

SECRET_KEY_PATTERN = r"\A(?!\.\Z|\.\.)[a-zA-Z0-9_\-.]+\Z"


def check_key(value: str) -> str:
    if value.lower() == SECRET_DUMMY_KEY:
        raise t.DataError(f"Illegal key {value!r}")
    return value


def check_base64(value: str) -> str:
    try:
        base64.b64decode(value)
    except Exception as exc:
        raise t.DataError(str(exc))
    return value


secret_key_validator = (
    t.String(min_length=1, max_length=253) & t.Regexp(SECRET_KEY_PATTERN) >> check_key
)
secret_value_validator = t.String(max_length=1024 * 1024) >> check_base64
secret_request_validator = t.Dict(
    {
        "key": secret_key_validator,
        "value": secret_value_validator,
        t.Key("org_name", optional=True): t.String(min_length=1, max_length=253)
        | t.Null(),
        t.Key("project_name", optional=True): t.String(min_length=1, max_length=253),
    }
)
secret_response_validator = t.Dict(
    {
        "key": t.String,
        "owner": t.String,
        "org_name": t.String() | t.Null(),
        "project_name": t.String,
    }
)
secret_list_response_validator = t.List(secret_response_validator)
secret_unwrap_validator = t.Dict(
    {
        t.Key("org_name"): t.String(min_length=1, max_length=253) | t.Null(),
        t.Key("project_name"): t.String(min_length=1, max_length=253) | t.Null(),
        t.Key("target_namespace"): t.String(min_length=1, max_length=253),
    }
)
