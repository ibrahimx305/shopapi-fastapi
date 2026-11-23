"""
ShopAPI — a store REST API built with FastAPI.

Backend work by Ibrahim Khan (Full-Stack Developer):
- FastAPI + SQLite (stdlib sqlite3, no ORM magic — plain, readable SQL)
- JWT authentication (HS256, signed with stdlib hmac)
- Passwords hashed with scrypt (stdlib hashlib)
- Products CRUD, orders, per-user data isolation
- Automatic interactive docs at /docs (Swagger UI, built into FastAPI)

Run:  uvicorn main:app --reload   →  http://localhost:8000/docs
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

# NOTE: to keep dependencies minimal (fastapi + uvicorn only), email is a plain str.
class UserIn(BaseModel):
    name: str
    email: str
    password: str


class LoginIn(BaseModel):
    email: str
    password: str


class ProductIn(BaseModel):
    name: str
    description: str = ""
    price: float
    stock: int = 0
    category: str = "general"


class ProductOut(ProductIn):
    id: int
    owner_id: int


class OrderItemIn(BaseModel):
    product_id: int
    quantity: int = 1


class OrderIn(BaseModel):
    items: List[OrderItemIn]


SECRET = os.environ.get("JWT_SECRET", "shopapi-dev-secret-change-in-production")
DB_PATH = os.path.join(os.path.dirname(__file__), "shop.db")
bearer = HTTPBearer(auto_error=False)

app = FastAPI(title="ShopAPI", description="Store REST API — FastAPI + SQLite + JWT auth", version="1.0.0")


# ---------------- database ----------------
@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL REFERENCES users(id),
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                price REAL NOT NULL,
                stock INTEGER DEFAULT 0,
                category TEXT DEFAULT 'general'
            );
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                items TEXT NOT NULL,
                total REAL NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        count = conn.execute("SELECT COUNT(*) AS c FROM products").fetchone()["c"]
        if count == 0:
            # Seed demo products under a demo seller account
            seller = conn.execute("SELECT id FROM users WHERE email='demo@shopapi.dev'").fetchone()
            if seller is None:
                conn.execute(
                    "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                    ("Demo Seller", "demo@shopapi.dev", hash_password("demo123")),
                )
                seller_id = conn.execute("SELECT id FROM users WHERE email='demo@shopapi.dev'").fetchone()["id"]
            else:
                seller_id = seller["id"]
            seed = [
                ("Wireless Noise-Cancelling Headphones", "Bluetooth over-ear, 30h battery", 59.99, 25, "electronics"),
                ("Smart Watch Series 8", "AMOLED display, heart-rate tracking", 89.50, 40, "electronics"),
                ("Men's Running Shoes", "Lightweight breathable mesh", 45.00, 60, "fashion"),
                ("Stainless Steel Water Bottle 1L", "Vacuum insulated, 24h cold", 16.95, 120, "home"),
            ]
            conn.executemany(
                "INSERT INTO products (owner_id, name, description, price, stock, category) VALUES (?, ?, ?, ?, ?, ?)",
                [(seller_id, *row) for row in seed],
            )


# ---------------- password hashing (scrypt) ----------------
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"{salt.hex()}:{digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    salt_hex, digest_hex = stored.split(":")
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
    return hmac.compare_digest(digest.hex(), digest_hex)


# ---------------- minimal JWT (HS256) ----------------
def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def sign_token(user_id: int) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64(json.dumps({"sub": user_id, "exp": int(time.time()) + 7 * 24 * 3600}).encode())
    sig = _b64(hmac.new(SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"


def verify_token(token: str) -> Optional[int]:
    try:
        header, body, sig = token.split(".")
        expected = _b64(hmac.new(SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if payload["exp"] < int(time.time()):
            return None
        return int(payload["sub"])
    except Exception:
        return None


def current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> int:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing token")
    user_id = verify_token(creds.credentials)
    if user_id is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    return user_id


# ---------------- auth routes ----------------
@app.post("/auth/register", status_code=201)
def register(data: UserIn):
    if len(data.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    with db() as conn:
        if conn.execute("SELECT id FROM users WHERE email=?", (data.email.lower(),)).fetchone():
            raise HTTPException(409, "An account with this email already exists")
        cur = conn.execute(
            "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
            (data.name, data.email.lower(), hash_password(data.password)),
        )
        user_id = cur.lastrowid
    return {"token": sign_token(user_id), "user": {"id": user_id, "name": data.name, "email": data.email.lower()}}


@app.post("/auth/login")
def login(data: LoginIn):
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE email=?", (data.email.lower(),)).fetchone()
    if row is None or not verify_password(data.password, row["password_hash"]):
        raise HTTPException(401, "Invalid email or password")
    return {"token": sign_token(row["id"]), "user": {"id": row["id"], "name": row["name"], "email": row["email"]}}


@app.get("/auth/me")
def me(user_id: int = Depends(current_user)):
    with db() as conn:
        row = conn.execute("SELECT id, name, email FROM users WHERE id=?", (user_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "User not found")
    return dict(row)


# ---------------- product routes ----------------
@app.get("/products", response_model=List[ProductOut])
def list_products(category: Optional[str] = None, search: Optional[str] = None):
    query = "SELECT * FROM products"
    clauses, params = [], []
    if category:
        clauses.append("category = ?")
        params.append(category)
    if search:
        clauses.append("name LIKE ?")
        params.append(f"%{search}%")
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    with db() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


@app.get("/products/{product_id}", response_model=ProductOut)
def get_product(product_id: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "Product not found")
    return dict(row)


@app.post("/products", response_model=ProductOut, status_code=201)
def create_product(data: ProductIn, user_id: int = Depends(current_user)):
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO products (owner_id, name, description, price, stock, category) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, data.name, data.description, data.price, data.stock, data.category),
        )
        row = conn.execute("SELECT * FROM products WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(row)


@app.patch("/products/{product_id}", response_model=ProductOut)
def update_product(product_id: int, data: ProductIn, user_id: int = Depends(current_user)):
    with db() as conn:
        row = conn.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Product not found")
        if row["owner_id"] != user_id:
            raise HTTPException(403, "You can only edit your own products")
        conn.execute(
            "UPDATE products SET name=?, description=?, price=?, stock=?, category=? WHERE id=?",
            (data.name, data.description, data.price, data.stock, data.category, product_id),
        )
        row = conn.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
    return dict(row)


@app.delete("/products/{product_id}", status_code=204)
def delete_product(product_id: int, user_id: int = Depends(current_user)):
    with db() as conn:
        row = conn.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Product not found")
        if row["owner_id"] != user_id:
            raise HTTPException(403, "You can only delete your own products")
        conn.execute("DELETE FROM products WHERE id=?", (product_id,))
    return None


# ---------------- order routes ----------------
@app.post("/orders", status_code=201)
def create_order(data: OrderIn, user_id: int = Depends(current_user)):
    if not data.items:
        raise HTTPException(400, "Order must contain at least one item")
    with db() as conn:
        total = 0.0
        snapshot = []
        for item in data.items:
            row = conn.execute("SELECT * FROM products WHERE id=?", (item.product_id,)).fetchone()
            if row is None:
                raise HTTPException(404, f"Product {item.product_id} not found")
            if row["stock"] < item.quantity:
                raise HTTPException(400, f"Not enough stock for '{row['name']}'")
            conn.execute("UPDATE products SET stock = stock - ? WHERE id=?", (item.quantity, item.product_id))
            total += row["price"] * item.quantity
            snapshot.append({"product_id": row["id"], "name": row["name"], "price": row["price"], "quantity": item.quantity})
        cur = conn.execute(
            "INSERT INTO orders (user_id, items, total) VALUES (?, ?, ?)",
            (user_id, json.dumps(snapshot), round(total, 2)),
        )
        order_id = cur.lastrowid
    return {"id": order_id, "items": snapshot, "total": round(total, 2)}


@app.get("/orders")
def my_orders(user_id: int = Depends(current_user)):
    with db() as conn:
        rows = conn.execute("SELECT * FROM orders WHERE user_id=? ORDER BY id", (user_id,)).fetchall()
    return [{"id": r["id"], "items": json.loads(r["items"]), "total": r["total"], "created_at": r["created_at"]} for r in rows]


@app.get("/health")
def health():
    return {"status": "ok", "app": "ShopAPI", "docs": "/docs"}


init_db()
