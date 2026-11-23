# ShopAPI — Store REST API (FastAPI)

A complete backend REST API for a small store: user accounts, products and orders — built with **FastAPI + SQLite** and JWT authentication.

Built by **Ibrahim Khan** — Full-Stack Developer (React, Next.js, Node.js & Python).

## Features
- **Auth:** register / login with JWT tokens (HS256), passwords hashed with scrypt
- **Products:** public listing with category filter + search; create / edit / delete for the product's owner only
- **Orders:** place an order (stock is checked and reduced), list your own orders with totals
- **Validation:** request/response schemas with Pydantic; clear HTTP errors
- **Docs:** interactive Swagger UI built in — open `/docs` and try every endpoint in the browser
- **Zero heavy deps:** only `fastapi` + `uvicorn`; database, JWT and password hashing use Python's standard library (sqlite3, hmac, hashlib)

## Run it locally
```bash
pip install -r requirements.txt
uvicorn main:app --reload
# API:  http://localhost:8000
# Docs: http://localhost:8000/docs
```
On first run the database is created and seeded with demo products.
Demo seller account: `demo@shopapi.dev` / `demo123`

## Endpoints
| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/auth/register` | — | Create account, returns token |
| POST | `/auth/login` | — | Log in, returns token |
| GET | `/auth/me` | Bearer | Current user |
| GET | `/products` | — | List products (`?category=`, `?search=`) |
| GET | `/products/{id}` | — | One product |
| POST | `/products` | Bearer | Create a product |
| PATCH | `/products/{id}` | Bearer | Edit your product |
| DELETE | `/products/{id}` | Bearer | Delete your product |
| POST | `/orders` | Bearer | Place an order `{ items: [{product_id, quantity}] }` |
| GET | `/orders` | Bearer | My orders |
| GET | `/health` | — | Health check |

## Project structure
```
main.py           The whole API: db layer, auth, JWT, products, orders
requirements.txt  fastapi, uvicorn
shop.db           Created at runtime (git-ignored)
```

## Notes
Set `JWT_SECRET` in the environment for production use. The data layer is plain SQL, so moving from SQLite to PostgreSQL is a small, contained change.
