from flask.cli import AppGroup
from sqlalchemy.exc import SQLAlchemyError

from main.modules.auth.controller import RoleController, UserController

create_cli = AppGroup("create")


@create_cli.command("admin")
def create_admin():
    """
    To create admin user.
    """
    try:
        admin_role = RoleController.get_role_by_name("admin")
        if not admin_role:
            print("Error: Admin role not found in database.")

        email = input("Enter admin's email: ")
        username = input("Enter admin's username: ")
        password = input("Enter admin's password: ")
        employee_code = input("Enter admin's employee code: ")

        user_data = {
            "password": password,
            "username": username,
            "email": email,
            "approved": True,
            "approved_by": "system",
            "role_id": admin_role.role_id,
            "employee_code": employee_code,
        }
        user_id, error = UserController.create_user(user_data)
        if user_id:
            print("Admin User Created!")
        else:
            print("Error: ", error)
    except SQLAlchemyError as e:
        if "doesn't exist" in str(e):
            print("Error: Table not found, Check if database is migrated")
        else:
            print("Error in creating Admin user. ==> ", e)


def init_app(app):
    app.cli.add_command(create_cli)
