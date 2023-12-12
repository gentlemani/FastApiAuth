import mysql.connector
import os
from dotenv import load_dotenv

load_dotenv()

# *** Database connections ***


def auth_db_conn() -> mysql.connector:
    db = mysql.connector.connect(
        host=os.getenv('DB_AUTH_HOST'), port=os.getenv('DB_AUTH_PORT'), database=os.getenv('DB_AUTH_DATABASE'),
        user=os.getenv('DB_AUTH_USERNAME'), password=os.getenv('DB_AUTH_PASSWORD'))
    return db


def db_connection() -> mysql.connector:
    db = mysql.connector.connect(
        host=os.getenv('DB_HOST'), port=os.getenv('DB_PORT'), database=os.getenv('DB_DATABASE'),
        user=os.getenv('DB_USERNAME'), password=os.getenv('DB_PASSWORD'))
    return db
