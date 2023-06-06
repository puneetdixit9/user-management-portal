import enum

from sqlalchemy import or_
from werkzeug.security import check_password_hash, generate_password_hash
from main.exceptions import RecordNotFoundError

from main.modules.auth.model import Department
# from main.modules.jwt.controller import JWTController


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
        department = Department.get(dept_id)
        if department:
            Department.delete(dept_id=dept_id)
            return {"status": "ok"}
        raise RecordNotFoundError(f"dept_id '{dept_id}' not found")


# class AuthUserController:
#     class ROLES(enum.Enum):
#         """
#         ROLE is an enum of valid roles in the system.
#         """
#
#         ADMIN = "admin"
#         USER = "user"
#
#     @classmethod
#     def get_current_auth_user(cls) -> AuthUser:
#         """
#         Get current logged-in user.
#         :return AuthUser:
#         """
#         identity = JWTController.get_user_identity()
#         return AuthUser.query.filter_by(id=identity["user_id"]).first()
#
#     @classmethod
#     def create_new_user(cls, user_data: dict) -> (AuthUser, dict):
#         """
#         To create new user
#         :param user_data:
#         :return (AuthUser, error_data):
#         """
#         error_data = {}
#         user_by_email = AuthUser.query.filter_by(email=user_data["email"]).first()
#         user_by_username = AuthUser.query.filter_by(username=user_data["username"]).first()
#         if user_by_email or user_by_username:
#             param = "username" if user_by_username else "email"
#             error_data["error"] = f"user already exists with provided {param}"
#         else:
#             user_data["password"] = generate_password_hash(user_data["password"])
#             auth_user = AuthUser.create(user_data)
#             return auth_user, error_data
#         return None, error_data
#
#     @classmethod
#     def update_user_password(cls, update_password_data: dict) -> (dict, str):
#         """
#         To update user password.
#         :param update_password_data:
#         :return dict, error_msg:
#         """
#         auth_user = cls.get_current_auth_user()
#         if check_password_hash(auth_user.password, update_password_data["old_password"]):
#             if check_password_hash(auth_user.password, update_password_data["new_password"]):
#                 return {}, "new password can not same as old password"
#             auth_user.update({"password": generate_password_hash(update_password_data["new_password"])})
#             return {"status": "success"}, ""
#         return {}, "Old password is invalid"
#
#     @classmethod
#     def get_token(cls, login_data: dict) -> [dict, str]:
#         """
#         To get jwt bearer token on login
#         :param login_data:
#         :return dict:
#         """
#         token = {}
#         email_or_username = login_data.get("username") or login_data.get("email")
#         auth_user = AuthUser.query.filter(
#             or_(AuthUser.email == email_or_username, AuthUser.username == email_or_username)
#         ).first()
#         if not auth_user:
#             return token, f"user not found with {email_or_username}"
#
#         if check_password_hash(auth_user.password, login_data["password"]):
#             return JWTController.get_access_and_refresh_token(auth_user), ""
#         return token, "wrong password"
#
#     @classmethod
#     def logout(cls):
#         """
#         On logout to block jwt token.
#         :return:
#         """
#         blocked_token = JWTController.block_jwt_token()
#         return {"msg": f"{blocked_token.type.capitalize()} token successfully revoked"}
#
#     @classmethod
#     def refresh_access_token(cls) -> dict:
#         """
#         To get a new access token using refresh token.
#         :return:
#         """
#         return JWTController.get_access_token_from_refresh_token()
