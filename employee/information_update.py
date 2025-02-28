from config.config import DATABASE_URI
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.mybank_db import Users
from security.encryption import aes_256_gcm_encrypt
from security.key_management import retrieve_key_from_db
from security.audit import log_operation

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)


def employee_update_customer_info(employee_user, customer_id, new_phone=None, new_address=None, new_name=None):
    """
    员工协助客户更新个人信息
    """
    session = Session()
    try:
        # 检查客户是否存在且是 client
        customer = session.query(Users).filter_by(user_id=customer_id).first()
        if not customer or customer.role.value != 'client':
            raise Exception("The specified user is not a valid customer.")

        # 检查至少有一个字段需要更新
        if not any([new_phone, new_address, new_name]):
            raise Exception("No fields to update.")

        # 获取加密密钥
        aes_key, key_version = retrieve_key_from_db(key_name=customer.key_name)

        # 更新电话
        if new_phone:
            phone_nonce, encrypted_phone = aes_256_gcm_encrypt(new_phone.encode('utf-8'), aes_key)
            customer.encrypted_phone = encrypted_phone
            customer.phone_nonce = phone_nonce

        # 更新地址
        if new_address:
            address_nonce, encrypted_address = aes_256_gcm_encrypt(new_address.encode('utf-8'), aes_key)
            customer.encrypted_address = encrypted_address
            customer.address_nonce = address_nonce

        # 更新姓名
        if new_name:
            name_nonce, encrypted_name = aes_256_gcm_encrypt(new_name.encode('utf-8'), aes_key)
            customer.encrypted_name = encrypted_name
            customer.name_nonce = name_nonce

        # 记录更新来源
        customer.last_updated_by = employee_user.user_id
        customer.last_updated_at = datetime.datetime.now(tz=datetime.timezone.utc)

        session.commit()

        # 记录操作
        update_fields = []
        if new_phone: update_fields.append("phone")
        if new_address: update_fields.append("address")
        if new_name: update_fields.append("name")

        log_operation(
            employee_user.user_id,
            "update_customer_info",
            f"Updated customer {customer_id} information: {', '.join(update_fields)}"
        )

        return customer
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()