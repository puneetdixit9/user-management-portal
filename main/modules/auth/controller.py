import enum

from sqlalchemy import or_
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
        ids = []
        errors = []
        for role in roles:
            role_id = Role.create(role).role_id
            ids.append(role_id)
        return ids, errors

    @classmethod
    def get_all_roles(cls) -> list:
        return Role.get_all()

    @classmethod
    def get_role_by_id(cls, role_id: int):
        role = Role.get(role_id, to_json=True)
        if role:
            return role
        raise RecordNotFoundError(f"role_id '{role_id}' not found")

    @classmethod
    def update_role(cls, role_id: int, data: dict):
        role = Role.get(role_id)
        if role:
            role.update(data)
            return {"status": "ok"}
        raise RecordNotFoundError(f"role_id '{role_id}' not found")

    @classmethod
    def delete_role(cls, role_id: int):
        role = Role.get(role_id)
        if role:
            Role.delete(role_id=role_id)
            return {"status": "ok"}
        raise RecordNotFoundError(f"role_id '{role_id}' not found")


class UserController:
    @classmethod
    def create_user(cls, user_data: dict):
        error = ""
        user_id = None
        user = User.filter(email_address=user_data["email_address"], only_first=True)
        if user:
            error = f"user already exists with email : '{user_data['email_address']}'"
        else:
            user_data["password"] = generate_password_hash(user_data["password"])
            user_id = User.create(user_data).user_id
        return user_id, error

    @classmethod
    def get_current_auth_user(cls):
        """
        Get current logged-in user.
        :return AuthUser:
        """
        identity = JWTController.get_user_identity()
        return User.get(identity["user_id"])

    @classmethod
    def update_user_password(cls, update_password_data: dict) -> (dict, str):
        """
        To update user password.
        :param update_password_data:
        :return dict, error_msg:
        """
        auth_user = cls.get_current_auth_user()
        if check_password_hash(auth_user.password, update_password_data["old_password"]):
            if check_password_hash(auth_user.password, update_password_data["new_password"]):
                return {}, "new password can not same as old password"
            auth_user.update({"password": generate_password_hash(update_password_data["new_password"])})
            return {"status": "success"}, ""
        return {}, "Old password is invalid"

    @classmethod
    def get_token(cls, login_data: dict) -> [dict, str]:
        """
        To get jwt bearer token on login
        :param login_data:
        :return dict:
        """
        token = {}
        user = User.filter(email_address=login_data["email_address"], only_first=True)
        if not user:
            return token, f"user not found with '{login_data['email_address']}'."

        if check_password_hash(user.password, login_data["password"]):
            return JWTController.get_access_and_refresh_token(user), ""
        return token, "wrong password"

    @classmethod
    def logout(cls):
        """
        On logout to block jwt token.
        :return:
        """
        blocked_token = JWTController.block_jwt_token()
        return {"msg": f"{blocked_token.type.capitalize()} token successfully revoked"}

    @classmethod
    def refresh_access_token(cls) -> dict:
        """
        To get a new access token using refresh token.
        :return:
        """
        return JWTController.get_access_token_from_refresh_token()
