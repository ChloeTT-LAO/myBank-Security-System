from sqlalchemy import create_engine
from .mybank_db import Base


# 生成所有表
def create_all_tables():
    # 修改连接字符串，替换为你自己的 PostgreSQL 用户名、密码、数据库名等信息
    engine = create_engine("postgresql+psycopg2://postgres:011017@localhost:5432/mybank_db")
    Base.metadata.create_all(engine)
    print("所有表已通过 SQLAlchemy 自动创建！")


if __name__ == "__main__":
    create_all_tables()