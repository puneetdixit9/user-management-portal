from flask import jsonify, make_response, request, session
from flask_restx import Namespace, Resource

from main.decorators.token_from_cookie import verify_token
from main.decorators.user_role import allowed_roles
from main.exceptions.errors import PathNotFoundError
from main.modules.auth.controller import (
    DepartmentController,
    DepartmentSubFunctionController,
    PermissionController,
    RoleController,
    UserController,
)
from main.modules.auth.schema_validator import (
    ApproveUserSchema,
    DepartmentSchema,
    DepartmentSubFunctionSchema,
    LogInSchema,
    PermissionSchema,
    RoleSchema,
    SignUpSchema,
    UpdatePassword,
    UpdateUserSchema,
    UserPermissionsSchema,
)
from main.utils import get_data_from_request_or_raise_validation_error


class Departments(Resource):
    method_decorators = [verify_token()]

    @staticmethod
    def get(dept_id: int = None):
        if not dept_id:
            return make_response(jsonify(DepartmentController.get_all_departments()))
        return make_response(jsonify(DepartmentController.get_dept_by_id(dept_id)))

    @staticmethod
    def put(dept_id: int = None):
        if not dept_id:
            raise PathNotFoundError(request.method)
        data = get_data_from_request_or_raise_validation_error(DepartmentSchema, request.json)
        return make_response(jsonify(DepartmentController.update_department(dept_id, data)))

    @staticmethod
    def delete(dept_id: int = None):
        if not dept_id:
            raise PathNotFoundError(request.method)
        return make_response(jsonify(DepartmentController.delete_department(dept_id)))

    @staticmethod
    def post():
        data = get_data_from_request_or_raise_validation_error(DepartmentSchema, request.json, many=True)
        ids, errors = DepartmentController.add_departments(data)
        return make_response(jsonify(ids=ids, errors=errors), 201 if ids else 409)


class DepartmentSubFunction(Resource):
    # method_decorators = [verify_token()]

    @staticmethod
    @verify_token()
    def post():
        data = get_data_from_request_or_raise_validation_error(DepartmentSubFunctionSchema, request.json, many=True)
        ids, errors = DepartmentSubFunctionController.add_department_sub_function(data)
        return make_response(jsonify(ids=ids, errors=errors), 201 if ids else 409)

    @staticmethod
    def get():
        return make_response(DepartmentSubFunctionController.get_all_sub_functions())


class Roles(Resource):
    # method_decorators = [verify_token()]

    @staticmethod
    def get():
        return make_response(jsonify(RoleController.get_all_roles()))

    @staticmethod
    @verify_token()
    def post():
        data = get_data_from_request_or_raise_validation_error(RoleSchema, request.json, many=True)
        ids, errors = RoleController.add_roles(data)
        return make_response(jsonify(ids=ids, errors=errors), 201 if ids else 409)


class Role(Resource):
    method_decorators = [verify_token()]

    @staticmethod
    def get(role_id: int):
        return make_response(jsonify(RoleController.get_role_by_id(role_id)))

    @staticmethod
    def put(role_id: int):
        data = get_data_from_request_or_raise_validation_error(RoleSchema, request.json)
        return make_response(jsonify(RoleController.update_role(role_id, data)))

    @staticmethod
    def delete(role_id: int):
        return make_response(jsonify(RoleController.delete_role(role_id)))


class Signup(Resource):
    @staticmethod
    def post():
        data = get_data_from_request_or_raise_validation_error(SignUpSchema, request.json)
        user_id, error = UserController.create_user(data)
        return make_response(jsonify(error=error), 409) if error else make_response(jsonify(user_id=user_id), 201)


class Login(Resource):
    @staticmethod
    def post():
        """
        To get tokens (access and refresh) using valid user credentials.
        :return:
        """
        data = get_data_from_request_or_raise_validation_error(LogInSchema, request.json)
        token, error = UserController.login(data)
        if error:
            return make_response(jsonify(error=error["msg"]), error["code"])
        # response = make_response(jsonify(status="ok"), 200)
        response = make_response(token)
        # session["access_token"] = token["access_token"].encode("utf-8")
        # response.set_cookie(
        #     "access_token",
        #     token["access_token"].encode("utf-8"),
        #     httponly=True,
        #     expires=datetime.now() + timedelta(days=1),
        # )
        return response


class VerifyToken(Resource):
    method_decorators = [verify_token()]

    @staticmethod
    def get():
        return make_response(jsonify(UserController.get_current_user_identity()))


# class Refresh(Resource):
#     method_decorators = [jwt_required(refresh=True)]
#
#     @staticmethod
#     def get():
#         """
#         To update the access token using a valid refresh token.
#         :return:
#         """
#         return make_response(jsonify(UserController.refresh_access_token()))


class ChangePassword(Resource):
    method_decorators = [verify_token()]

    @staticmethod
    def put():
        """
        To change the password of logged-in user.
        :return:
        """
        data = get_data_from_request_or_raise_validation_error(UpdatePassword, request.json)
        response, error_msg = UserController.update_user_password(data)
        if error_msg:
            return make_response(jsonify(error=error_msg), 401)
        return make_response(jsonify(response))


class Logout(Resource):
    method_decorators = [verify_token()]

    @staticmethod
    def get():
        """
        To log out the user.
        :return:
        """
        session.clear()
        return make_response(jsonify(status="ok"))


class User(Resource):
    method_decorators = [verify_token()]

    @staticmethod
    def get(user_id: int):
        """
        To get user details.
        :param user_id:
        """
        response = UserController.get_user_details(user_id)
        return make_response(jsonify(response))

    @staticmethod
    def put(user_id: int):
        """
        To update user details.
        :param user_id:
        :return:
        """
        data = get_data_from_request_or_raise_validation_error(UpdateUserSchema, request.json)
        UserController.update_user(user_id, data)
        return make_response(jsonify(status="ok"))


class ApproveUser(Resource):
    method_decorators = [allowed_roles(["admin"]), verify_token()]

    @staticmethod
    def post(user_id: int):
        data = get_data_from_request_or_raise_validation_error(ApproveUserSchema, request.json)
        UserController.approve_user_account(user_id, data)
        return make_response(jsonify(status="ok"))


class UserAccounts(Resource):
    method_decorators = [allowed_roles(["admin"]), verify_token()]

    @staticmethod
    def post():
        return make_response(UserController.get_users(request.json if request.is_json else {}))


class UserPermissions(Resource):
    method_decorators = [verify_token()]

    @staticmethod
    def get(user_id: int = None):
        return make_response(UserController.get_user_permissions(user_id))

    @staticmethod
    @allowed_roles(["admin"])
    def post(user_id: int = None):
        if not user_id:
            raise PathNotFoundError(request.method)
        data = get_data_from_request_or_raise_validation_error(UserPermissionsSchema, request.json)
        UserController.add_permissions_to_user(user_id, data["permission_ids"])
        return make_response(jsonify(status="ok"))


class Permissions(Resource):
    method_decorators = [verify_token()]

    @staticmethod
    def get():
        return make_response(PermissionController.get_permissions())

    @staticmethod
    def post():
        data = get_data_from_request_or_raise_validation_error(PermissionSchema, request.json, many=True)
        ids, errors = PermissionController.add_permissions(data)
        return make_response(jsonify(ids=ids, errors=errors), 201 if ids else 409)


auth_namespace = Namespace("auth-api", description="Auth Operations")
auth_namespace.add_resource(Departments, "/departments", "/departments/<int:dept_id>")
auth_namespace.add_resource(DepartmentSubFunction, "/sub-function")
auth_namespace.add_resource(Roles, "/roles")
auth_namespace.add_resource(Role, "/role/<role_id>")

auth_namespace.add_resource(Signup, "/signup")
auth_namespace.add_resource(Login, "/login")
# auth_namespace.add_resource(Refresh, "/refresh")
auth_namespace.add_resource(ChangePassword, "/change_password")
auth_namespace.add_resource(Logout, "/logout")
auth_namespace.add_resource(VerifyToken, "/verify")
auth_namespace.add_resource(User, "/user/<int:user_id>")
auth_namespace.add_resource(ApproveUser, "/approve-user/<int:user_id>")
auth_namespace.add_resource(UserAccounts, "/users")
auth_namespace.add_resource(UserPermissions, "/user-permissions", "/user-permissions/<int:user_id>")
auth_namespace.add_resource(Permissions, "/permissions")
