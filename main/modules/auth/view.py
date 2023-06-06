from flask import jsonify, make_response, request
from flask_jwt_extended import jwt_required
from flask_restx import Namespace, Resource

from main.modules.auth.controller import DepartmentController
from main.modules.auth.schema_validator import LogInSchema, SignUpSchema, UpdatePassword, DepartmentSchema
from main.utils import get_data_from_request_or_raise_validation_error


class Departments(Resource):
    def get(self):
        return make_response(jsonify(DepartmentController.get_all_departments()))

    def post(self):
        data = get_data_from_request_or_raise_validation_error(DepartmentSchema, request.json, many=True)
        ids, errors = DepartmentController.add_departments(data)
        return make_response(jsonify(ids=ids, errors=errors), 201)


class Department(Resource):
    def get(self, dept_id: int):
        return make_response(jsonify(DepartmentController.get_dept_by_id(dept_id)))

    def put(self, dept_id: int):
        data = get_data_from_request_or_raise_validation_error(DepartmentSchema, request.json)
        return make_response(jsonify(DepartmentController.update_department(dept_id, data)))

    def delete(self, dept_id: int):
        return make_response(jsonify(DepartmentController.delete_department(dept_id)))


# class SignUp(Resource):
#     def post(self):
#         """
#         To create a new user.
#         :return user_id:
#         """
#         data = get_data_from_request_or_raise_validation_error(SignUpSchema, request.json)
#         user, error_data = AuthUserController.create_new_user(data)
#         if not user:
#             return make_response(jsonify(error_data), 409)
#         return make_response(jsonify(id=user.id), 201)
#
#
# class Login(Resource):
#     def post(self):
#         """
#         To get tokens (access and refresh) using valid user credentials.
#         :return:
#         """
#         data = get_data_from_request_or_raise_validation_error(LogInSchema, request.json)
#         token, error_msg = AuthUserController.get_token(data)
#         if error_msg:
#             return make_response(jsonify(error=error_msg), 403)
#         return make_response(jsonify(token), 200)
#
#
# class Refresh(Resource):
#     method_decorators = [jwt_required(refresh=True)]
#
#     def get(self):
#         """
#         To update the access token using a valid refresh token.
#         :return:
#         """
#         return jsonify(AuthUserController.refresh_access_token())
#
#
# class ChangePassword(Resource):
#     method_decorators = [jwt_required()]
#
#     def put(self):
#         """
#         To change the password of logged-in user.
#         :return:
#         """
#         data = get_data_from_request_or_raise_validation_error(UpdatePassword, request.json)
#         response, error_msg = AuthUserController.update_user_password(data)
#         if error_msg:
#             return make_response(jsonify(error=error_msg), 401)
#         return jsonify(response)
#
#
# class Logout(Resource):
#     method_decorators = [jwt_required(verify_type=False)]
#
#     def get(self):
#         """
#         To log out the user.
#         :return:
#         """
#         return jsonify(AuthUserController.logout())


auth_namespace = Namespace("auth", description="Auth Operations")
auth_namespace.add_resource(Departments, "/departments")
auth_namespace.add_resource(Department, "/department/<dept_id>")

# auth_namespace.add_resource(SignUp, "/signup")
# auth_namespace.add_resource(Login, "/login")
# auth_namespace.add_resource(Refresh, "/refresh")
# auth_namespace.add_resource(ChangePassword, "/change_password")
# auth_namespace.add_resource(Logout, "/logout")
