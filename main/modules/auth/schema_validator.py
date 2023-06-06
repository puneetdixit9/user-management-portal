from marshmallow import Schema, fields
from marshmallow.validate import Length


class DepartmentSchema(Schema):
    dept_name = fields.String(required=True)


class RoleSchema(Schema):
    role_name = fields.String(required=True)


class SignUpSchema(Schema):
    """
    To validate signup request body.
    """

    user_name = fields.String()
    first_name = fields.String(required=True)
    middle_name = fields.String()
    last_name = fields.String(required=True)
    manager_name = fields.String()
    employee_code = fields.String()
    email_address = fields.Email(required=True)
    password = fields.String(required=True, validate=Length(min=8))  # noqa
    mobile_number = fields.String()
    status = fields.String()
    status_changed_by = fields.String()
    status_changed_on = fields.Date()
    usage_count = fields.Integer()
    last_login_on = fields.Date()
    func_id = fields.Integer()
    is_active = fields.Integer()
    role_id = fields.Integer()
    dept_id = fields.Integer()


class LogInSchema(Schema):
    """
    In this schema we defined the required json to log in any user.
    """

    email_address = fields.Email(required=True)
    password = fields.String(required=True)


class UpdatePassword(Schema):
    """
    Required schema to update the password
    """

    old_password = fields.String(required=True)
    new_password = fields.String(required=True, validate=Length(min=8))  # noqa
