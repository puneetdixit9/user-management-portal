from sqlalchemy import ForeignKey
from main.db import BaseModel, db


class User(BaseModel):
    """
    Model for auth_user.
    """

    __tablename__ = "user"

    user_id = db.Column(db.BIGINT, primary_key=True, autoincrement=True)
    user_name = db.Column(db.String(100))
    first_name = db.Column(db.String(100))
    middle_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    manager_name = db.Column(db.String(100))
    employee_code = db.Column(db.String(100))
    email_address = db.Column(db.String(100))
    password = db.Column(db.String(100))
    mobile_number = db.Column(db.String(100))
    status = db.Column(db.String(100))
    status_changed_by = db.Column(db.String(100))
    status_changed_on = db.Column(db.Date)
    usage_count = db.Column(db.Integer)
    last_login_on = db.Column(db.Date)
    func_id = db.Column(db.BIGINT)
    is_active = db.Column(db.Integer)
    role_id = db.Column(db.BIGINT, ForeignKey('role.role_id'))
    dept_id = db.Column(db.BIGINT, ForeignKey('department.dept_id'))


class UserRoleDeptMapping(BaseModel):
    """
    Model for user role and dept mapping.
    """

    __tablename__ = "user_role_dept_mapping"

    user_role_dept_mapping_id = db.Column(db.BIGINT, primary_key=True, autoincrement=True)
    func_id = db.Column(db.BIGINT)
    user_id = db.Column(db.BIGINT, ForeignKey('user.user_id'))
    role_id = db.Column(db.BIGINT, ForeignKey('role.role_id'))
    dept_id = db.Column(db.BIGINT, ForeignKey('department.dept_id'))
    is_active = db.Column(db.Integer)


class Role(BaseModel):
    """
    Model for user role.
    """

    __tablename__ = "role"

    role_id = db.Column(db.BIGINT, primary_key=True, autoincrement=True)
    role_name = db.Column(db.String(100), unique=True)
    is_active = db.Column(db.INTEGER)


class FuncDept(BaseModel):
    """
    Model for function with department.
    """

    __tablename__ = "function_with_department"

    func_id = db.Column(db.BIGINT, primary_key=True, autoincrement=True)
    dept_id = db.Column(db.INTEGER, ForeignKey('department.dept_id'))
    dept_name = db.Column(db.String(100))
    sub_function = db.Column(db.String(100))
    is_active = db.Column(db.INTEGER)


class Department(BaseModel):
    """
    Model for department.
    """

    __tablename__ = "department"

    dept_id = db.Column(db.BIGINT, primary_key=True, autoincrement=True)
    is_active = db.Column(db.INTEGER)
    dept_name = db.Column(db.String(100), unique=True)
