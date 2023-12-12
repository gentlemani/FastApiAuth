from datetime import datetime, timedelta, date
from typing import Annotated
import mysql.connector
import json
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
import connection

# Command to start the app:
# uvicorn server:app --reload

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


app = FastAPI()

# *** User authentication functions ***


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db: mysql.connector, username: str):

    cursor = db.cursor()
    # -1 is used because it doesn't exist a -1 id value
    encontro = -1
    try:
        cursor.execute("select id,username from usuarios")
        for (id, username_c) in cursor:
            if username == username_c:
                encontro = id
    except mysql.connector.Error as error:
        print("Failed to update record to database: {}".format(error))
    finally:
        cursor.close()

    if encontro != -1:
        user_dict = []
        try:
            cursor = db.cursor()
            cursor.execute(
                "select username,hashed_password,full_name,email,disabled from usuarios where id = %s", (encontro,))
            for (username, password, full_name, email, disabled) in cursor:
                user_dict = {
                    'username': username,
                    'hashed_password': password,
                    'full_name': full_name,
                    'email': email,
                    'disabled': bool(disabled)
                }
            return UserInDB(**user_dict)
        except mysql.connector.Error as error:
            print("Failed to update record to database: {}".format(error))
        finally:
            cursor.close()


def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(connection.auth_db_conn(), username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = authenticate_user(
        connection.auth_db_conn(), form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return [{"item_id": "Foo", "owner": current_user.username}]


# Sql operations with no return values (select statement is not consider in this function)
def sql_statement(sql, values):
    inserted = False
    db = connection.db_connection()
    cursor = db.cursor()
    try:
        cursor.execute(sql, values)
        db.commit()
        inserted = True
    except mysql.connector.Error as error:
        print("Failed to update record to database: {}".format(error))
    finally:
        cursor.close()
    return {'status': inserted}


def procesa_dato(objecto):
    if isinstance(objecto, (datetime, date)):
        return objecto.isoformat()

# *** Api pages ***


@app.get("/",)
def index(current_user: Annotated[User, Depends(get_current_active_user)]):
    return "{'message': 'ok'}"


# Create a new employee
@app.post("/actors/")
def crear(current_user: Annotated[User, Depends(get_current_active_user)], nombre: str, apellido: str):
    sql = "INSERT INTO actor (first_name, last_name) VALUES (%s, %s)"
    values = (nombre, apellido)
    return sql_statement(sql, values)


# Update emplpyee
@app.put("/actors/{id}")
def actualizar(current_user: Annotated[User, Depends(get_current_active_user)], id: int, nombre: str = None, apellido: str = None):
    if not nombre and not apellido:
        return {'status': False}
    sql = "UPDATE actor set "
    values = []
    # Creation of the sql statement according to the data to be updated
    if nombre:
        sql += "first_name = %s "
        values.append(nombre)
    if apellido:
        values.append(apellido)
        if nombre:
            sql += ", "
        sql += "last_name = %s "
    sql += "WHERE actor_id = %s"
    values.append(id)
    values = tuple(values)
    return sql_statement(sql, values)


@app.delete("/actors/{id}")
def eliminar(current_user: Annotated[User, Depends(get_current_active_user)], id: int):
    sql = "Delete from actor where actor_id = %s"
    return sql_statement(sql, (id,))


@app.get("/actors")
def actors(current_user: Annotated[User, Depends(get_current_active_user)]):
    db = connection.db_connection()
    cursor = db.cursor()
    cursor.execute("select * from actor")
    resultado = cursor.fetchall()
    return json.dumps(resultado, default=procesa_dato)


# Search an actor by name
@app.get("/actors/{nombre}")
def actors(current_user: Annotated[User, Depends(get_current_active_user)], nombre: str):
    db = connection.db_connection()
    cursor = db.cursor()
    cursor.execute(
        "select * from actor where first_name = %s", (nombre,))
    resultado = cursor.fetchall()
    return json.dumps(resultado, default=procesa_dato)
