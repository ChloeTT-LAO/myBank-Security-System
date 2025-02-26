DATABASE_URI = "postgresql+psycopg2://postgres:011017@localhost:5432/mybank_db"

from cryptography.fernet import Fernet
DEFAULT_FERNET_KEY = Fernet.generate_key()