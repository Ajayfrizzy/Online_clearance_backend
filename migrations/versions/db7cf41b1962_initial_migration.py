"""Initial migration

Revision ID: db7cf41b1962
Revises: 
Create Date: 2025-05-12 00:26:18.959195

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'db7cf41b1962'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('staff',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('staff_id', sa.String(length=20), nullable=False),
    sa.Column('full_name', sa.String(length=100), nullable=False),
    sa.Column('department', sa.String(length=100), nullable=False),
    sa.Column('email', sa.String(length=100), nullable=False),
    sa.Column('password_hash', sa.String(length=200), nullable=False),
    sa.Column('phone_number', sa.String(length=20), nullable=False),
    sa.Column('role', sa.String(length=20), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('staff_id')
    )
    op.create_table('students',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('matric_number', sa.String(length=20), nullable=False),
    sa.Column('first_name', sa.String(length=50), nullable=False),
    sa.Column('last_name', sa.String(length=50), nullable=False),
    sa.Column('department', sa.String(length=100), nullable=False),
    sa.Column('faculty', sa.String(length=100), nullable=False),
    sa.Column('gender', sa.String(length=10), nullable=False),
    sa.Column('email', sa.String(length=100), nullable=False),
    sa.Column('phone_number', sa.String(length=20), nullable=False),
    sa.Column('password_hash', sa.String(length=200), nullable=False),
    sa.Column('program', sa.String(length=20), nullable=False),
    sa.Column('profile_photo', sa.String(length=200), nullable=True),
    sa.Column('registration_date', sa.DateTime(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('matric_number')
    )
    op.create_table('clearance_requests',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('student_id', sa.Integer(), nullable=False),
    sa.Column('request_date', sa.DateTime(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('comments', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['student_id'], ['students.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('clearance_approvals',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('clearance_request_id', sa.Integer(), nullable=False),
    sa.Column('staff_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('remarks', sa.Text(), nullable=True),
    sa.Column('timestamp', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['clearance_request_id'], ['clearance_requests.id'], ),
    sa.ForeignKeyConstraint(['staff_id'], ['staff.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('supporting_documents',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('clearance_request_id', sa.Integer(), nullable=False),
    sa.Column('file_path', sa.String(length=200), nullable=False),
    sa.Column('upload_date', sa.DateTime(), nullable=False),
    sa.Column('file_type', sa.String(length=50), nullable=False),
    sa.ForeignKeyConstraint(['clearance_request_id'], ['clearance_requests.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('supporting_documents')
    op.drop_table('clearance_approvals')
    op.drop_table('clearance_requests')
    op.drop_table('students')
    op.drop_table('staff')
    # ### end Alembic commands ###
