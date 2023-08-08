from datetime import datetime

from flask import g
from werkzeug.security import check_password_hash, generate_password_hash

from main.db import db
from main.exceptions import CustomValidationError, RecordNotFoundError
from main.modules.auth.model import Department, Role, User
from main.modules.jwt.controller import JWTController
from main.utils import get_query_including_filters


class DepartmentController:
    @classmethod
    def add_departments(cls, departments: list[dict]) -> (list, list):
        """
        To add new departments.
        :param departments:
        :return:
        """
        ids = []
        errors = []
        for department in departments:
            dept_id = Department.create(department).dept_id
            ids.append(dept_id)
        return ids, errors

    @classmethod
    def get_all_departments(cls) -> list:
        """
        To get all departments.
        :return:
        """
        return Department.get_all()

    @classmethod
    def get_dept_by_id(cls, dept_id: int) -> dict:
        """
        To get department data by id.
        :param dept_id:
        :return:
        """
        department = Department.get(dept_id, to_json=True)
        if department:
            return department
        raise RecordNotFoundError(f"dept_id '{dept_id}' not found")

    @classmethod
    def update_department(cls, dept_id: int, data: dict) -> dict:
        """
        To update department.
        :param dept_id:
        :param data:
        :return:
        """
        department = Department.get(dept_id)
        if department:
            department.update(data)
            return {"status": "ok"}
        raise RecordNotFoundError(f"dept_id '{dept_id}' not found")

    @classmethod
    def delete_department(cls, dept_id) -> dict:
        """
        To delete a department.
        :param dept_id:
        :return:
        """
        department = Department.get(dept_id)
        if department:
            Department.delete(dept_id=dept_id)
            return {"status": "ok"}
        raise RecordNotFoundError(f"dept_id '{dept_id}' not found")


class FuncDeptController:
    pass


class RoleController:
    @classmethod
    def add_roles(cls, roles: list[dict]) -> (list, list):
        """
        To add roles
        :param roles:
        :return:
        """
        ids = []
        errors = []
        for role in roles:
            if Role.filter(role_name=role["role_name"], only_first=True):
                errors.append(f"'{role['role_name']}' role already exists")
                continue
            role_id = Role.create(role).role_id
            ids.append(role_id)
        return ids, errors

    @classmethod
    def get_all_roles(cls) -> list:
        """
        To get all roles
        :return:
        """
        return Role.get_all()

    @classmethod
    def get_role_by_id(cls, role_id: int):
        """
        To get role by id.
        :param role_id:
        :return:
        """
        role = Role.get(role_id, to_json=True)
        if role:
            return role
        raise RecordNotFoundError(f"role_id '{role_id}' not found")

    @classmethod
    def update_role(cls, role_id: int, data: dict):
        """
        To update role.
        :param role_id:
        :param data:
        :return:
        """
        role = Role.get(role_id)
        if role:
            role.update(data)
            return {"status": "ok"}
        raise RecordNotFoundError(f"role_id '{role_id}' not found")

    @classmethod
    def delete_role(cls, role_id: int):
        """
        To delete a role.
        :param role_id:
        :return:
        """
        role = Role.get(role_id)
        if role:
            Role.delete(role_id=role_id)
            return {"status": "ok"}
        raise RecordNotFoundError(f"role_id '{role_id}' not found")


class UserController:
    @classmethod
    def create_user(cls, user_data: dict) -> (int, str):
        """
        To create a new user.
        :param user_data:
        :return:
        """
        error = ""
        user_id = None
        query = get_query_including_filters(
            db, User, {"op_or": {"email": user_data["email"], "user_name": user_data["user_name"]}}
        )
        user = query.first()
        if user:
            if user.email == user_data["email"]:
                error = f"user already exists with email : '{user_data['email']}'"
            else:
                error = f"user already exits with user_name : '{user_data['user_name']}'"
        else:
            user_data["password"] = generate_password_hash(user_data["password"])
            user_id = User.create(user_data).user_id
        return user_id, error

    @classmethod
    def update_user_password(cls, update_password_data: dict) -> (dict, str):
        """
        To update user password.
        :param update_password_data:
        :return dict, error_msg:
        """
        user = g.user
        if check_password_hash(user.password, update_password_data["old_password"]):
            if check_password_hash(user.password, update_password_data["new_password"]):
                return {}, "new password can not same as old password"
            user.update({"password": generate_password_hash(update_password_data["new_password"])})
            return {"status": "ok"}, ""
        return {}, "Old password is invalid"

    @classmethod
    def login(cls, login_data: dict) -> (dict, str):
        """
        To get jwt bearer token on login
        :param login_data:
        :return dict:
        """
        token = dict()
        error = dict()
        if login_data.get("email"):
            user = User.filter(email=login_data["email"], only_first=True)
        else:
            user = User.filter(user_name=login_data["user_name"], only_first=True)
        if not user:
            error["msg"] = f"user not found with '{login_data.get('email') or login_data.get('user_name')}'."
            error["code"] = 403
        elif not user.approved:
            error["msg"] = "Account approval is still pending."
            error["code"] = 412
        elif check_password_hash(user.password, login_data["password"]):
            token = JWTController.get_access_and_refresh_token(user)
            user.update({"last_login_on": datetime.now()})
        else:
            error["msg"] = "wrong password"
            error["code"] = 403
        return token, error

    @classmethod
    def approve_user_account(cls, user_id: int, data: dict):
        """
        To approve user account.
        :param user_id:
        :param data:
        :return:
        """
        logged_in_user = cls.get_current_user_identity()
        user = User.filter(user_id=user_id, only_first=True)
        if not user:
            raise RecordNotFoundError(f"User not found with user_id: {user_id}")

        if data.get("role_id") and not RoleController.get_role_by_id(data["role_id"]):
            raise CustomValidationError(f"Invalid role_id : {data['role_id']}")

        data["approved"] = True
        data["approved_by"] = logged_in_user["email"]
        data["modified_by"] = logged_in_user["email"]
        user.update(data)

    @staticmethod
    def get_pending_approval_users():
        """
        To get pending approval users.
        """
        return User.filter(approved=False, to_json=True)

    @staticmethod
    def get_current_user_identity():
        """
        To return the identity.
        """
        return {"email": g.user.email, "role": g.user.role.role_name, "user_id": g.user.user_id}

    @classmethod
    def logout(cls):
        """
        On logout to block jwt token.
        :return:
        """
        blocked_token = JWTController.block_jwt_token()
        return {"msg": f"{blocked_token.type.capitalize()} token successfully revoked"}

    @classmethod
    def get_user_details(cls, user_id: int):
        """
        To get the user details
        :param user_id:
        :return:
        """
        user = User.get(user_id, to_json=True)
        if not user:
            raise RecordNotFoundError
        return user

    @classmethod
    def update_user_details(cls, user_id: int, data: dict):
        """
        To update user details.
        :param user_id:
        :param data:
        :return:
        """
        user = User.get(user_id)
        if not user:
            raise RecordNotFoundError
        user.update(data)
