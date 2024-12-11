from fastapi import FastAPI, HTTPException, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from datetime import datetime, timedelta
from starlette.staticfiles import StaticFiles
import psycopg2
import bcrypt
import secrets

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

DB_CONFIG = {
    "dbname": "authdb",
    "user": "postgres",
    "password": "password",
    "host": "localhost",
    "port": 5432
}

HOSPITAL_DB_CONFIG = {
    "dbname": "hospital",
    "user": "postgres",
    "password": "password",
    "host": "localhost",
    "port": 5432,
}

class AuthRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    temp_token: str
    token_expiry: datetime

class AuthRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    temp_token: str
    token_expiry: datetime

def hash_password(plain_password):
    hashed_password = bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt())
    return hashed_password.decode()

def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))

def db_connection():
    return psycopg2.connect(**DB_CONFIG)

def hospital_db_connection():
    return psycopg2.connect(**HOSPITAL_DB_CONFIG)

def generate_random_string(length: int = 32) -> str:
    return secrets.token_urlsafe(length)

def create_temporary_hospital_user(username: str):
    temp_password = secrets.token_urlsafe(8)
    hashed_password = bcrypt.hashpw(temp_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    token_expiry = datetime.now() + timedelta(minutes=30)

    conn = hospital_db_connection()
    try:
        with conn.cursor() as cursor:
            # Add or update the temporary user
            cursor.execute("""
                INSERT INTO hospital_users (username, temp_password, token_expiry)
                VALUES (%s, %s, %s)
                ON CONFLICT (username) DO UPDATE
                SET temp_password = EXCLUDED.temp_password, token_expiry = EXCLUDED.token_expiry
            """, (username, hashed_password, token_expiry))
            conn.commit()
        return temp_password, token_expiry
    finally:
        conn.close()
    
@app.get("/", response_class=HTMLResponse)
def generate_temp_token_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/generate-temp-token")
async def generate_temp_token(
    auth_request: AuthRequest = None,  
    username: str = Form(None),        
    password: str = Form(None) 
):
   
    # Parse input
    if auth_request:  # JSON request
        username = auth_request.username
        password = auth_request.password
    elif username and password:  # Form request
        pass
    else:
        raise HTTPException(status_code=400, detail="Invalid input format")


    auth_conn = db_connection()
    hospital_conn = hospital_db_connection()

    try:
        with auth_conn.cursor() as auth_cursor:
            # Validate user credentials in AuthDB
            auth_cursor.execute(
                "SELECT permanent_password FROM auth_tokens WHERE username = %s",
                (username,)
            )
            user = auth_cursor.fetchone()

            if not user:
                raise HTTPException(status_code=401, detail="Invalid username or password.")

            permanent_password = user[0]
            if not verify_password(password, permanent_password):
                raise HTTPException(status_code=401, detail="Invalid username or password.")

            # Generate temporary token and expiry
            temp_token = generate_random_string(16)
            token_expiry = datetime.now() + timedelta(minutes=30)

            # Update AuthDB with temp_token and token_expiry
            auth_cursor.execute(
                "UPDATE auth_tokens SET temp_token = %s, token_expiry = %s WHERE username = %s",
                (temp_token, token_expiry, username)
            )
            auth_conn.commit()

        with hospital_conn.cursor() as hospital_cursor:
            # Generate plain temp_password and its hash
            plain_temp_password = generate_random_string(12)  # e.g., 12-character password
            hashed_temp_password = hash_password(temp_token)

            # Update HospitalDB with hashed_temp_password and token_expiry
            hospital_cursor.execute(
                """
                UPDATE hospital_users
                SET temp_password = %s, token_expiry = %s
                WHERE username = %s
                """,
                (hashed_temp_password, token_expiry, username)
            )
            hospital_conn.commit()

        return JSONResponse(content={
            "temp_token": temp_token,
            "token_expiry": token_expiry.isoformat()
            })


    except Exception as e:
        auth_conn.rollback()
        hospital_conn.rollback()
        print(f"Error during token generation: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error.")
    finally:
        auth_conn.close()
        hospital_conn.close()


@app.get("/access-hospital", response_class=HTMLResponse)
async def access_hospital_page(request: Request):
    return templates.TemplateResponse("access_hospital.html", {"request": request})

@app.post("/access-hospital")
async def access_hospital(
    auth_request: AuthRequest = None,  # JSON request body
    username: str = Form(None),        # Form field for username
    password: str = Form(None)         # Form field for password
):
    # Parse input: JSON payload or form data

    if auth_request:  # JSON request
        username = auth_request.username
        temp_token = auth_request.password
    elif username and password:  # Form request
        temp_token = password
    else:
        raise HTTPException(status_code=400, detail="Invalid input format. Provide JSON or form data.")

    conn = hospital_db_connection()

    try:
        with conn.cursor() as cursor:
            # Fetch the hashed temp_password and expiry time for the user
            cursor.execute(
                "SELECT temp_password, token_expiry FROM hospital_users WHERE username = %s",
                (username,),
            )
            user = cursor.fetchone()

            if not user:
                raise HTTPException(status_code=401, detail="User not found")

            hashed_password, token_expiry = user

            # Check if the token is expired
            if datetime.now() > token_expiry:
                raise HTTPException(status_code=401, detail="Temporary credentials expired")
            
            # Verify the temporary token using bcrypt
            if not bcrypt.checkpw(temp_token.encode("utf-8"), hashed_password.encode("utf-8")):
                raise HTTPException(status_code=401, detail="Invalid temporary password")

            # Access granted
            return JSONResponse(content={"message": "Access granted to the Hospital database"})

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
    finally:
        conn.close()



@app.get("/auth-admin", response_class=HTMLResponse)
def auth_admin_page(request: Request):
    return templates.TemplateResponse("auth_admin.html", {"request": request})


@app.post("/auth-admin")
async def auth_admin(
    auth_request: AuthRequest = None,
    username: str = Form(None),        
    password: str = Form(None) 
):

    if auth_request:  # JSON request
        username = auth_request.username
        temp_token = auth_request.password
    elif username and password:  # Form request
        temp_token = password
    else:
        raise HTTPException(status_code=400, detail="Invalid input format. Provide JSON or form data.")

    try:
        # Check if the provided username and password match the ones in DB_CONFIG
        if username == DB_CONFIG['user'] and password == DB_CONFIG['password']:
            # Redirect to the /add-user page on successful authentication
            return RedirectResponse(url="/add_user", status_code=302)
        else:
            # If username or password is incorrect, return an error message
            raise HTTPException(status_code=401, detail="Invalid username or password")
        
    except Exception as e:
        print(f"Error during authentication: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/add_user", response_class=HTMLResponse)
def add_user_page(request: Request):
    return templates.TemplateResponse("add_user.html", {"request": request})

@app.post("/add_user")
async def add_user(
    auth_request: AuthRequest = None,  
    username: str = Form(None),        
    password: str = Form(None)     
):
    # Parse input
    if auth_request:  # JSON request
        username = auth_request.username
        password = auth_request.password
    elif username and password:  # Form request
        pass
    else:
        raise HTTPException(status_code=400, detail="Invalid input format")

    # Connect to both databases
    auth_conn = db_connection()  # AuthDB connection
    hospital_conn = hospital_db_connection()  # HospitalDB connection

    try:
        # Add the user to the AuthDB
        auth_cursor = auth_conn.cursor()
        auth_cursor.execute(
            "INSERT INTO auth_tokens (username, permanent_password) VALUES (%s, %s)",
            (username, hash_password(password))
        )
        auth_conn.commit()
        
        # Add the user to the HospitalDB (initialize their profile)
        hospital_cursor = hospital_conn.cursor()
        hospital_cursor.execute(
            """
            INSERT INTO hospital_users (username, temp_password, token_expiry)
            VALUES (%s, '', '1970-01-01 00:00:00') 
            ON CONFLICT (username) DO NOTHING
            """,
            (username,)
        )
        hospital_conn.commit()

        auth_cursor.close()
        hospital_cursor.close()

        return JSONResponse({"message": f"User {username} added successfully to both AuthDB and HospitalDB."})

    except Exception as e:
        print(f"Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to add user to databases")
    finally:
        auth_conn.close()
        hospital_conn.close()