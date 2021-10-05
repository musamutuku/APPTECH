"""empty message

Revision ID: bb12ba205930
Revises: 009b91167d0a
Create Date: 2021-10-04 18:48:15.028373

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'bb12ba205930'
down_revision = '009b91167d0a'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('profile_pic', sa.String(length=100), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'profile_pic')
    # ### end Alembic commands ###
