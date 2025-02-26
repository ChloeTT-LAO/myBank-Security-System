import base64

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from config.config import DATABASE_URI
from config.mybank_db import Users
from security.encryption import generate_hmac_key


engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)

session = Session()
user = session.query(Users).filter_by(user_id=8).first()
hmac_key = generate_hmac_key()
user.hmac_key = base64.b64encode(hmac_key).decode('utf-8')
email = "admin@gmail.com"
safe_email = email.replace("@", "_at_").replace(".", "_dot_")
with open(f"employee_secret/{safe_email}_hmac_key.txt", "wb") as private_file:
    private_file.write(hmac_key)
    private_file.close()

session.commit()
session.close()
