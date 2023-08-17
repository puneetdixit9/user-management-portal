from functools import wraps

from flask import g, jsonify, make_response


def allowed_roles(roles: list):
    """
    This decorator function is used for verifying allowed roles using jwt token and user role.
    :param roles:
    :return:
    """

    def role_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if g.user.role.role_name not in roles:
                return make_response(jsonify({"error": "Unauthorized User!!"}), 401)
            return f(*args, **kwargs)

        return decorated

    return role_required
