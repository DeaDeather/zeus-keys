"""
Zeus Midnight — сервер лицензионных ключей.
БД: PostgreSQL (Railway Postgres — данные сохраняются между рестартами).

Переменные окружения:
    DATABASE_URL       — автоматически задаётся Railway при подключении Postgres
    ZEUS_ADMIN_TOKEN   — токен для /deactivate (поменяй в Railway Variables)

Запуск локально:
    pip install fastapi uvicorn psycopg2-binary
    DATABASE_URL=postgresql://... python key_server.py
"""
import os
import time

import psycopg2
import psycopg2.extras
from contextlib import closing
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

DATABASE_URL  = os.environ["DATABASE_URL"]  # Railway подставляет автоматически
ADMIN_TOKEN   = os.environ.get("ZEUS_ADMIN_TOKEN", "change-me-now")

app = FastAPI(title="Zeus Midnight License Server")


@app.get("/app")
def webapp():
    """Отдаёт Telegram Mini App (webapp/index.html)."""
    return FileResponse("webapp/index.html")


def db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn


def init_db():
    with closing(db()) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS keys (
                    key TEXT PRIMARY KEY,
                    hwid TEXT,
                    active INTEGER DEFAULT 1,
                    max_activations INTEGER DEFAULT 1,
                    activations INTEGER DEFAULT 0,
                    expires_at BIGINT,
                    resets_left INTEGER DEFAULT 2,
                    note TEXT,
                    created_at BIGINT
                )
            """)
        conn.commit()

init_db()


class ActivateReq(BaseModel):
    key: str
    hwid: str

class ValidateReq(BaseModel):
    key: str
    hwid: str

class DeactivateReq(BaseModel):
    key: str
    admin_token: str

class ResetHwidReq(BaseModel):
    key: str


def _norm(key: str) -> str:
    return key.strip().upper()


def _row_status(row, hwid):
    if row is None:
        return False, "not_found"
    if not row["active"]:
        return False, "revoked"
    if row["expires_at"] and row["expires_at"] < time.time():
        return False, "expired"
    if row["hwid"] and row["hwid"] != hwid:
        return False, "hwid_mismatch"
    return True, "ok"


@app.post("/activate")
def activate(req: ActivateReq):
    key = _norm(req.key)
    with closing(db()) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM keys WHERE key = %s", (key,))
            row = cur.fetchone()
            if row is None:
                raise HTTPException(404, "Ключ не найден")
            if not row["active"]:
                raise HTTPException(403, "Ключ отозван")
            if row["expires_at"] and row["expires_at"] < time.time():
                raise HTTPException(403, "Срок действия ключа истёк")

            if row["hwid"] == req.hwid:
                return {"ok": True, "status": "already_active"}

            if row["hwid"] is None:
                if row["activations"] >= row["max_activations"]:
                    raise HTTPException(403, "Превышен лимит активаций")
                cur.execute(
                    "UPDATE keys SET hwid = %s, activations = activations + 1 WHERE key = %s",
                    (req.hwid, key),
                )
                conn.commit()
                return {"ok": True, "status": "activated"}

            raise HTTPException(409, "Ключ уже активирован на другом устройстве")


@app.post("/validate")
def validate(req: ValidateReq):
    key = _norm(req.key)
    with closing(db()) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM keys WHERE key = %s", (key,))
            row = cur.fetchone()
            ok, reason = _row_status(row, req.hwid)
            if not ok:
                raise HTTPException(403, reason)
            return {"ok": True, "expires_at": row["expires_at"]}


@app.post("/deactivate")
def deactivate(req: DeactivateReq):
    if req.admin_token != ADMIN_TOKEN:
        raise HTTPException(401, "Неверный admin_token")
    key = _norm(req.key)
    with closing(db()) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE keys SET hwid = NULL, activations = 0 WHERE key = %s", (key,))
            conn.commit()
            if cur.rowcount == 0:
                raise HTTPException(404, "Ключ не найден")
        return {"ok": True}


@app.post("/reset_hwid")
def reset_hwid(req: ResetHwidReq):
    key = _norm(req.key)
    with closing(db()) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM keys WHERE key = %s", (key,))
            row = cur.fetchone()
            if row is None:
                raise HTTPException(404, "Ключ не найден")
            if not row["active"]:
                raise HTTPException(403, "Ключ отозван")
            if row["resets_left"] <= 0:
                raise HTTPException(403, "Лимит сбросов исчерпан, обратитесь к продавцу")
            cur.execute(
                "UPDATE keys SET hwid = NULL, activations = 0, resets_left = resets_left - 1 WHERE key = %s",
                (key,),
            )
            conn.commit()
        return {"ok": True, "resets_left": row["resets_left"] - 1}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
