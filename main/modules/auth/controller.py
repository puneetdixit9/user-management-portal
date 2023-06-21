from datetime import datetime

from flask import g
from werkzeug.security import check_password_hash, generate_password_hash

from main.exceptions import RecordNotFoundError
from main.modules.auth.model import Department, Role, User
from main.modules.jwt.controller import JWTController


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
        user = User.filter(email=user_data["email"], only_first=True)
        if user:
            error = f"user already exists with email : '{user_data['email']}'"
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
        error = str()
        user = User.filter(email=login_data["email"], only_first=True)
        if not user:
            error = f"user not found with '{login_data['email']}'."
        elif check_password_hash(user.password, login_data["password"]):
            token = JWTController.get_access_and_refresh_token(user)
            user.update({"last_login_on": datetime.now()})
        else:
            error = "wrong password"
        return token, error

    @classmethod
    def get_current_user_identity(cls):
        """
        To return the identity.
        """
        return {"email": g.user.email, "role": g.user.role, "user_id": g.user.user_id}

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
