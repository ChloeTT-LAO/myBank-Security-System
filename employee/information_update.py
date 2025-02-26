from config.config import DATABASE_URI
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.mybank_db import Users
from client.account import update_personal_info

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)

def employee_update_customer_info(employee_user, customer_id, **kwargs):
    """
    员工协助客户更新个人信息 (phone, address, name等)
    假设你已有 update_personal_info(user_id, new_phone, new_address, new_name)
    """

    # 检查 customer_id 是否真的 client
    session = Session()
    try:
        customer = session.query(Users).filter_by(user_id=customer_id).first()
        if not customer or customer.role != 'client':
            raise Exception("Invalid customer ID.")
    finally:
        session.close()

    # 调用你在 user_profile.py 中的函数
    return update_personal_info(customer_id, **kwargs)