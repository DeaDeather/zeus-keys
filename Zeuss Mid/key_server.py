"""
Zeus Midnight — сервер лицензионных ключей.

Запуск:
    pip install fastapi uvicorn
    python key_server.py

По умолчанию слушает http://0.0.0.0:8000
Хранилище — SQLite файл keys.db рядом со скриптом (создаётся сам).

Эндпоинты:
    POST /activate    {key, hwid}                   — первая активация: привязывает HWID к ключу
    POST /validate     {key, hwid}                   — проверка при каждом запуске программы
    POST /reset_hwid   {key}                         — юзер сам открепляет ключ от старого ПК (лимит resets_left)
    POST /deactivate   {key, admin_token}             — админ принудительно открепляет ключ от ПК

Ключами управляет manage_keys.py (добавление/список/отзыв/срок действия).
"""
import os
import sqlite3
import secrets
import time
from contextlib import closing

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys.db")

# Токен для административных операций (deactivate и т.п.).
# Поменяйте на свой и держите в секрете — лучше через переменную окружения.
ADMIN_TOKEN = os.environ.get("ZEUS_ADMIN_TOKEN", "change-me-now")

app = FastAPI(title="Zeus Midnight License Server")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with closing(db()) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                key TEXT PRIMARY KEY,
                hwid TEXT,                 -- NULL пока не активирован
                active INTEGER DEFAULT 1,  -- 0 = отозван вручную
                max_activations INTEGER DEFAULT 1,
                activations INTEGER DEFAULT 0,
                expires_at INTEGER,        -- unix timestamp или NULL = бессрочный
                resets_left INTEGER DEFAULT 2,  -- сколько раз юзер сам может сменить ПК
                note TEXT,
                created_at INTEGER
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
    """Возвращает (ok: bool, reason: str)"""
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
        row = conn.execute("SELECT * FROM keys WHERE key = ?", (key,)).fetchone()
        if row is None:
            raise HTTPException(404, "Ключ не найден")
        if not row["active"]:
            raise HTTPException(403, "Ключ отозван")
        if row["expires_at"] and row["expires_at"] < time.time():
            raise HTTPException(403, "Срок действия ключа истёк")

        # Уже привязан к этому HWID — просто подтверждаем
        if row["hwid"] == req.hwid:
            return {"ok": True, "status": "already_active"}

        # Ещё не привязан — привязываем, если есть свободные активации
        if row["hwid"] is None:
            if row["activations"] >= row["max_activations"]:
                raise HTTPException(403, "Превышен лимит активаций")
            conn.execute(
                "UPDATE keys SET hwid = ?, activations = activations + 1 WHERE key = ?",
                (req.hwid, key),
            )
            conn.commit()
            return {"ok": True, "status": "activated"}

        # Привязан к другому устройству
        raise HTTPException(409, "Ключ уже активирован на другом устройстве")


@app.post("/validate")
def validate(req: ValidateReq):
    key = _norm(req.key)
    with closing(db()) as conn:
        row = conn.execute("SELECT * FROM keys WHERE key = ?", (key,)).fetchone()
        ok, reason = _row_status(row, req.hwid)
        if not ok:
            raise HTTPException(403, reason)
        return {
            "ok": True,
            "expires_at": row["expires_at"],
        }


@app.post("/deactivate")
def deactivate(req: DeactivateReq):
    if req.admin_token != ADMIN_TOKEN:
        raise HTTPException(401, "Неверный admin_token")
    key = _norm(req.key)
    with closing(db()) as conn:
        cur = conn.execute(
            "UPDATE keys SET hwid = NULL, activations = 0 WHERE key = ?", (key,))
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(404, "Ключ не найден")
        return {"ok": True}


@app.post("/reset_hwid")
def reset_hwid(req: ResetHwidReq):
    """Пользователь сам открепляет ключ от старого ПК (например, после
    переустановки Windows), без обращения к админу. Лимит — resets_left,
    задаётся при создании ключа (manage_keys.py add --resets N)."""
    key = _norm(req.key)
    with closing(db()) as conn:
        row = conn.execute("SELECT * FROM keys WHERE key = ?", (key,)).fetchone()
        if row is None:
            raise HTTPException(404, "Ключ не найден")
        if not row["active"]:
            raise HTTPException(403, "Ключ отозван")
        if row["resets_left"] <= 0:
            raise HTTPException(403, "Лимит самостоятельных сбросов исчерпан, обратитесь к продавцу")
        conn.execute(
            "UPDATE keys SET hwid = NULL, activations = 0, resets_left = resets_left - 1 WHERE key = ?",
            (key,),
        )
        conn.commit()
        return {"ok": True, "resets_left": row["resets_left"] - 1}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
