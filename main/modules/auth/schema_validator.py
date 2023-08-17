from marshmallow import Schema, ValidationError, fields, validates_schema
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
    mobile_number = fields.String()
    status = fields.String()
    usage_count = fields.Integer()
    func_id = fields.Integer()
    is_active = fields.Boolean()
    role_id = fields.Integer()
    dept_id = fields.Integer()
    approved = fields.Boolean()


class SignUpSchema(UpdateUserSchema):
    """
    To Validate signup data
    """

    username = fields.String()
    email = fields.Email(required=True)
    password = fields.String(required=True, validate=Length(min=8))  # noqa
    first_name = fields.String(required=True)
    last_name = fields.String()
    employee_code = fields.String()
    manager_name = fields.String()
    dept_id = fields.Integer()
    role_id = fields.Integer()
    func_id = fields.Integer()


class LogInSchema(Schema):
    """
    In this schema we defined the required json to log in any user.
    """

    email = fields.Email()
    password = fields.String(required=True)
    username = fields.String()

    @validates_schema
    def validate_at_least_one(self, data, **kwargs):
        if "email" not in data and "username" not in data:
            raise ValidationError("At least one of 'email' or 'username' must be provided.")


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


class DepartmentSubFunctionSchema(Schema):
    """
    Required schema to approve user
    """

    dept_id = fields.Integer(required=True)
    sub_function_name = fields.String(required=True)


class PermissionSchema(Schema):
    """
    Required schema for permission.
    """

    permission = fields.String(required=True)
    application = fields.String(required=True)


class UserPermissionsSchema(Schema):
    """
    Required schema for user permissions.
    """

    permission_ids = fields.List(fields.Integer(), required=True)
