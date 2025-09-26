import base64

import trafaret as t

SECRET_DUMMY_KEY = "---neuro---"
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

org_project_validator = t.Dict(
    {
        t.Key("org_name", optional=True): t.String(min_length=1, max_length=253)
        | t.Null(),
        t.Key("project_name"): t.String(min_length=1, max_length=253),
    }
)
secret_request_validator = (
    t.Dict(
        {
            "key": secret_key_validator,
            "value": secret_value_validator,
        }
    )
    + org_project_validator
)

secret_response_validator = (
    t.Dict(
        {
            "key": t.String,
            "owner": t.String,
        }
    )
    + org_project_validator
)

secret_list_response_validator = t.List(secret_response_validator)

secret_with_value_response_validator = (
    t.Dict(
        {
            "key": t.String,
            "value": t.String,
            "owner": t.String,
        }
    )
    + org_project_validator
)
