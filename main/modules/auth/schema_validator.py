from marshmallow import Schema, fields
from marshmallow.validate import Length


class DepartmentSchema(Schema):
    dept_name = fields.String(required=True)


class RoleSchema(Schema):
    role_name = fields.String(required=True)


class UpdateUserSchema(Schema):
    """
    To validate signup request body.
    """

    first_name = fields.String()
    middle_name = fields.String()
    last_name = fields.String()
    manager_name = fields.String()
    employee_code = fields.String()
    mobile_number = fields.String()
    status = fields.String()
    usage_count = fields.Integer()
    func_id = fields.Integer()
    is_active = fields.Integer()
    role_id = fields.Integer()
    dept_id = fields.Integer()


class SignUpSchema(UpdateUserSchema):
    """
    To Validate signup data
    """

    user_name = fields.String()
    email = fields.Email(required=True)
    password = fields.String(required=True, validate=Length(min=8))  # noqa


class LogInSchema(Schema):
    """
    In this schema we defined the required json to log in any user.
    """

    email = fields.Email(required=True)
    password = fields.String(required=True)


class UpdatePassword(Schema):
    """
    Required schema to update the password
    """

    old_password = fields.String(required=True)
    new_password = fields.String(required=True, validate=Length(min=8))  # noqa


class ApproveUserSchema(Schema):
    """
    Required schema to approve user
    """

    role_id = fields.Integer()
    dept_id = fields.Integer()
