from sqlalchemy import ForeignKey

from main.db import BaseModel, db


class User(BaseModel):
    """
    Model for auth_user.
    """

    __tablename__ = "user"

    user_id = db.Column(db.BIGINT, primary_key=True, autoincrement=True)
    username = db.Column(db.String(100), unique=True)
    first_name = db.Column(db.String(100))
    middle_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    manager_name = db.Column(db.String(100))
    employee_code = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(255))
    mobile_number = db.Column(db.String(100))
    status = db.Column(db.String(100))
    status_changed_by = db.Column(db.String(100))
    status_changed_on = db.Column(db.DateTime)
    usage_count = db.Column(db.Integer)
    last_login_on = db.Column(db.DateTime)
    approved = db.Column(db.Boolean, default=False)
    approved_by = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    deactivated_by = db.Column(db.String(100))
    deactivated_on = db.Column(db.DateTime)

    func_id = db.Column(db.BIGINT, ForeignKey("department_sub_function.func_id"))
    role_id = db.Column(db.BIGINT, ForeignKey("role.role_id"))
    dept_id = db.Column(db.BIGINT, ForeignKey("department.dept_id"))

    role = db.relationship("Role", backref=db.backref("user", lazy=True))
    function = db.relationship("DepartmentSubFunction", backref=db.backref("user", lazy=True))
    dept = db.relationship("Department", backref=db.backref("user", lazy=True))

    def serialize(self) -> dict:
        """
        To convert the model object to a dict.
        :return:
        """
        return {c.name: getattr(self, c.name) for c in self.__table__.columns if c.name != "password"}

    @property
    def is_admin(self):
        """
        To check is user is Admin
        """
        return self.role.role_name == "admin"


class Permission(BaseModel):
    """
    Model for permission.
    """

    __tablename__ = "permission"

    permission_id = db.Column(db.BIGINT, primary_key=True, autoincrement=True)
    permission = db.Column(db.String(100), nullable=False)
    application = db.Column(db.String(100), nullable=False)
    model = db.Column(db.String(100))


class UserPermissions(BaseModel):
    """
    Model for user permissions
    """

    __tablename__ = "user_permission"

    user_permission_id = db.Column(db.BIGINT, primary_key=True, autoincrement=True)
    user_id = db.Column(db.BIGINT, ForeignKey("user.user_id"))
    permission_id = db.Column(db.BIGINT, ForeignKey("permission.permission_id"))

    permission = db.relationship("Permission", backref=db.backref("user_permission", lazy=True))


class UserRoleDeptMapping(BaseModel):
    """
    Model for user role and dept mapping.
    """

    __tablename__ = "user_role_dept_mapping"

    user_role_dept_mapping_id = db.Column(db.BIGINT, primary_key=True, autoincrement=True)
    func_id = db.Column(db.BIGINT)
    user_id = db.Column(db.BIGINT, ForeignKey("user.user_id"))
    role_id = db.Column(db.BIGINT, ForeignKey("role.role_id"))
    dept_id = db.Column(db.BIGINT, ForeignKey("department.dept_id"))
    is_active = db.Column(db.Boolean, default=True)


class Role(BaseModel):
    """
    Model for user role.
    """

    __tablename__ = "role"

    role_id = db.Column(db.BIGINT, primary_key=True, autoincrement=True)
    role_name = db.Column(db.String(100), unique=True)
    is_active = db.Column(db.Boolean, default=True)


class DepartmentSubFunction(BaseModel):
    """
    Model for function with department.
    """

    __tablename__ = "department_sub_function"

    func_id = db.Column(db.BIGINT, primary_key=True, autoincrement=True)
    dept_id = db.Column(db.BIGINT, ForeignKey("department.dept_id"), nullable=False)
    # dept_name = db.Column(db.String(100))
    sub_function_name = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)


class Department(BaseModel):
    """
    Model for department.
    """

    __tablename__ = "department"

    dept_id = db.Column(db.BIGINT, primary_key=True, autoincrement=True)
    is_active = db.Column(db.Boolean, default=True)
    dept_name = db.Column(db.String(100), unique=True)
