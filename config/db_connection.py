from sqlalchemy import create_engine
from .mybank_db import Base


# Generate all tables
def create_all_tables():
    # Modify the connection string, replacing it with your own PostgreSQL username, password, database name, and so on
    engine = create_engine("postgresql+psycopg2://postgres:011017@localhost:5432/mybank_db")
    Base.metadata.create_all(engine)
    print("All tables are automatically created using SQLAlchemy！")


if __name__ == "__main__":
    create_all_tables()