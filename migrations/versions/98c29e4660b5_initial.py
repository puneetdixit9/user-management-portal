"""initial

Revision ID: 98c29e4660b5
Revises:
Create Date: 2023-08-25 18:06:11.248161

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import text

# revision identifiers, used by Alembic.
revision = "98c29e4660b5"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "department",
        sa.Column("dept_id", sa.BIGINT(), autoincrement=True, nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("dept_name", sa.String(length=100), nullable=True),
        sa.Column("created_on", sa.DateTime(), server_default=sa.text("now()"), nullable=True),
        sa.Column("created_by", sa.String(length=50), nullable=True),
        sa.Column("modified_on", sa.DateTime(), nullable=True),
        sa.Column("modified_by", sa.String(length=50), nullable=True),
        sa.PrimaryKeyConstraint("dept_id"),
        sa.UniqueConstraint("dept_name"),
    )
    op.create_table(
        "permission",
        sa.Column("permission_id", sa.BIGINT(), autoincrement=True, nullable=False),
        sa.Column("permission", sa.String(length=100), nullable=False),
        sa.Column("application", sa.String(length=100), nullable=False),
        sa.Column("model", sa.String(length=100), nullable=True),
        sa.Column("created_on", sa.DateTime(), server_default=sa.text("now()"), nullable=True),
        sa.Column("created_by", sa.String(length=50), nullable=True),
        sa.Column("modified_on", sa.DateTime(), nullable=True),
        sa.Column("modified_by", sa.String(length=50), nullable=True),
        sa.PrimaryKeyConstraint("permission_id"),
    )
    op.create_table(
        "role",
        sa.Column("role_id", sa.BIGINT(), autoincrement=True, nullable=False),
        sa.Column("role_name", sa.String(length=100), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("created_on", sa.DateTime(), server_default=sa.text("now()"), nullable=True),
        sa.Column("created_by", sa.String(length=50), nullable=True),
        sa.Column("modified_on", sa.DateTime(), nullable=True),
        sa.Column("modified_by", sa.String(length=50), nullable=True),
        sa.PrimaryKeyConstraint("role_id"),
        sa.UniqueConstraint("role_name"),
    )
    op.create_table(
        "token_block_list",
        sa.Column("id", sa.BIGINT(), autoincrement=True, nullable=False),
        sa.Column("jti", sa.String(length=36), nullable=False),
        sa.Column("type", sa.String(length=16), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("created_on", sa.DateTime(), server_default=sa.text("now()"), nullable=True),
        sa.Column("created_by", sa.String(length=50), nullable=True),
        sa.Column("modified_on", sa.DateTime(), nullable=True),
        sa.Column("modified_by", sa.String(length=50), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("token_block_list", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_token_block_list_jti"), ["jti"], unique=False)

    op.create_table(
        "department_sub_function",
        sa.Column("func_id", sa.BIGINT(), autoincrement=True, nullable=False),
        sa.Column("dept_id", sa.BIGINT(), nullable=False),
        sa.Column("sub_function_name", sa.String(length=100), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("created_on", sa.DateTime(), server_default=sa.text("now()"), nullable=True),
        sa.Column("created_by", sa.String(length=50), nullable=True),
        sa.Column("modified_on", sa.DateTime(), nullable=True),
        sa.Column("modified_by", sa.String(length=50), nullable=True),
        sa.ForeignKeyConstraint(
            ["dept_id"],
            ["department.dept_id"],
        ),
        sa.PrimaryKeyConstraint("func_id"),
    )
    op.create_table(
        "user",
        sa.Column("user_id", sa.BIGINT(), autoincrement=True, nullable=False),
        sa.Column("username", sa.String(length=100), nullable=True),
        sa.Column("first_name", sa.String(length=100), nullable=True),
        sa.Column("middle_name", sa.String(length=100), nullable=True),
        sa.Column("last_name", sa.String(length=100), nullable=True),
        sa.Column("manager_name", sa.String(length=100), nullable=True),
        sa.Column("employee_code", sa.String(length=100), nullable=True),
        sa.Column("email", sa.String(length=100), nullable=True),
        sa.Column("password", sa.String(length=255), nullable=True),
        sa.Column("mobile_number", sa.String(length=100), nullable=True),
        sa.Column("status", sa.String(length=100), nullable=True),
        sa.Column("status_changed_by", sa.String(length=100), nullable=True),
        sa.Column("status_changed_on", sa.DateTime(), nullable=True),
        sa.Column("usage_count", sa.Integer(), nullable=True),
        sa.Column("last_login_on", sa.DateTime(), nullable=True),
        sa.Column("approved", sa.Boolean(), nullable=True),
        sa.Column("approved_by", sa.String(length=100), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("deactivated_by", sa.String(length=100), nullable=True),
        sa.Column("deactivated_on", sa.DateTime(), nullable=True),
        sa.Column("func_id", sa.BIGINT(), nullable=True),
        sa.Column("role_id", sa.BIGINT(), nullable=True),
        sa.Column("dept_id", sa.BIGINT(), nullable=True),
        sa.Column("created_on", sa.DateTime(), server_default=sa.text("now()"), nullable=True),
        sa.Column("created_by", sa.String(length=50), nullable=True),
        sa.Column("modified_on", sa.DateTime(), nullable=True),
        sa.Column("modified_by", sa.String(length=50), nullable=True),
        sa.ForeignKeyConstraint(
            ["dept_id"],
            ["department.dept_id"],
        ),
        sa.ForeignKeyConstraint(
            ["func_id"],
            ["department_sub_function.func_id"],
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["role.role_id"],
        ),
        sa.PrimaryKeyConstraint("user_id"),
        sa.UniqueConstraint("email"),
        sa.UniqueConstraint("employee_code"),
        sa.UniqueConstraint("username"),
    )
    op.create_table(
        "user_permission",
        sa.Column("user_permission_id", sa.BIGINT(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.BIGINT(), nullable=True),
        sa.Column("permission_id", sa.BIGINT(), nullable=True),
        sa.Column("created_on", sa.DateTime(), server_default=sa.text("now()"), nullable=True),
        sa.Column("created_by", sa.String(length=50), nullable=True),
        sa.Column("modified_on", sa.DateTime(), nullable=True),
        sa.Column("modified_by", sa.String(length=50), nullable=True),
        sa.ForeignKeyConstraint(
            ["permission_id"],
            ["permission.permission_id"],
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user.user_id"],
        ),
        sa.PrimaryKeyConstraint("user_permission_id"),
    )
    op.create_table(
        "user_role_dept_mapping",
        sa.Column("user_role_dept_mapping_id", sa.BIGINT(), autoincrement=True, nullable=False),
        sa.Column("func_id", sa.BIGINT(), nullable=True),
        sa.Column("user_id", sa.BIGINT(), nullable=True),
        sa.Column("role_id", sa.BIGINT(), nullable=True),
        sa.Column("dept_id", sa.BIGINT(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("created_on", sa.DateTime(), server_default=sa.text("now()"), nullable=True),
        sa.Column("created_by", sa.String(length=50), nullable=True),
        sa.Column("modified_on", sa.DateTime(), nullable=True),
        sa.Column("modified_by", sa.String(length=50), nullable=True),
        sa.ForeignKeyConstraint(
            ["dept_id"],
            ["department.dept_id"],
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["role.role_id"],
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user.user_id"],
        ),
        sa.PrimaryKeyConstraint("user_role_dept_mapping_id"),
    )
    # ### end Alembic commands ###

    # Create the 'admin' role
    op.execute(
        text(
            "INSERT INTO role (role_name, is_active, created_on, created_by) " "VALUES ('admin', true, now(), 'system')"
        )
    )
    # Create the 'user' role
    op.execute(
        text(
            "INSERT INTO role (role_name, is_active, created_on, created_by) " "VALUES ('user', true, now(), 'system')"
        )
    )


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table("user_role_dept_mapping")
    op.drop_table("user_permission")
    op.drop_table("user")
    op.drop_table("department_sub_function")
    with op.batch_alter_table("token_block_list", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_token_block_list_jti"))

    op.drop_table("token_block_list")
    op.drop_table("role")
    op.drop_table("permission")
    op.drop_table("department")
    # ### end Alembic commands ###
