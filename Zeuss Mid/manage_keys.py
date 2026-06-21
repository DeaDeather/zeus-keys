"""
Управление ключами Zeus Midnight (работает с той же keys.db, что и key_server.py).

Примеры:
    python manage_keys.py add                          # один ключ, бессрочный
    python manage_keys.py add --count 50 --days 365     # 50 ключей на год
    python manage_keys.py add --note "заказ #102" --activations 2
    python manage_keys.py list
    python manage_keys.py revoke ZEUS1-XXXXX-XXXXX-XXXXX
    python manage_keys.py unbind ZEUS1-XXXXX-XXXXX-XXXXX   # снять привязку к HWID
    python manage_keys.py extend ZEUS1-XXXXX-XXXXX-XXXXX --days 30
"""
import argparse
import os
import secrets
import sqlite3
import string
import time
from contextlib import closing

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys.db")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            hwid TEXT,
            active INTEGER DEFAULT 1,
            max_activations INTEGER DEFAULT 1,
            activations INTEGER DEFAULT 0,
            expires_at INTEGER,
            resets_left INTEGER DEFAULT 2,
            note TEXT,
            created_at INTEGER
        )
    """)
    return conn


def gen_key():
    alphabet = string.ascii_uppercase + string.digits
    groups = ["".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(4)]
    return "-".join(groups)


def cmd_add(args):
    with closing(db()) as conn:
        made = []
        for _ in range(args.count):
            key = gen_key()
            expires_at = int(time.time() + args.days * 86400) if args.days else None
            conn.execute(
                "INSERT INTO keys (key, max_activations, expires_at, resets_left, note, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (key, args.activations, expires_at, args.resets, args.note, int(time.time())),
            )
            made.append(key)
        conn.commit()
    print(f"Создано ключей: {len(made)}")
    for k in made:
        print(" ", k)


def cmd_list(args):
    with closing(db()) as conn:
        rows = conn.execute("SELECT * FROM keys ORDER BY created_at DESC").fetchall()
    for r in rows:
        status = "revoked" if not r["active"] else (
            "expired" if r["expires_at"] and r["expires_at"] < time.time() else "active")
        bound = r["hwid"][:12] + "…" if r["hwid"] else "—"
        print(f"{r['key']}  [{status:8}]  hwid={bound:14}  "
              f"act={r['activations']}/{r['max_activations']}  "
              f"resets={r['resets_left']}  "
              f"note={r['note'] or ''}")


def cmd_revoke(args):
    with closing(db()) as conn:
        cur = conn.execute("UPDATE keys SET active = 0 WHERE key = ?", (args.key.upper(),))
        conn.commit()
    print("Отозван" if cur.rowcount else "Ключ не найден")


def cmd_unbind(args):
    with closing(db()) as conn:
        cur = conn.execute(
            "UPDATE keys SET hwid = NULL, activations = 0 WHERE key = ?", (args.key.upper(),))
        conn.commit()
    print("Привязка снята" if cur.rowcount else "Ключ не найден")


def cmd_extend(args):
    with closing(db()) as conn:
        row = conn.execute("SELECT expires_at FROM keys WHERE key = ?", (args.key.upper(),)).fetchone()
        if not row:
            print("Ключ не найден")
            return
        base = row["expires_at"] if row["expires_at"] and row["expires_at"] > time.time() else time.time()
        new_exp = int(base + args.days * 86400)
        conn.execute("UPDATE keys SET expires_at = ?, active = 1 WHERE key = ?",
                     (new_exp, args.key.upper()))
        conn.commit()
    print(f"Новый срок действия: {time.strftime('%Y-%m-%d', time.localtime(new_exp))}")


def cmd_give_resets(args):
    with closing(db()) as conn:
        cur = conn.execute(
            "UPDATE keys SET resets_left = resets_left + ? WHERE key = ?",
            (args.amount, args.key.upper()),
        )
        conn.commit()
    print("Выдано" if cur.rowcount else "Ключ не найден")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("add")
    pa.add_argument("--count", type=int, default=1)
    pa.add_argument("--days", type=int, default=0, help="0 = бессрочный")
    pa.add_argument("--activations", type=int, default=1, help="сколько разных ПК можно активировать")
    pa.add_argument("--resets", type=int, default=2, help="сколько раз юзер сам может сбросить HWID")
    pa.add_argument("--note", default="")
    pa.set_defaults(func=cmd_add)

    sub.add_parser("list").set_defaults(func=cmd_list)

    pr = sub.add_parser("revoke"); pr.add_argument("key"); pr.set_defaults(func=cmd_revoke)
    pu = sub.add_parser("unbind"); pu.add_argument("key"); pu.set_defaults(func=cmd_unbind)
    pe = sub.add_parser("extend"); pe.add_argument("key"); pe.add_argument("--days", type=int, required=True)
    pe.set_defaults(func=cmd_extend)

    pg = sub.add_parser("give-resets"); pg.add_argument("key"); pg.add_argument("--amount", type=int, default=1)
    pg.set_defaults(func=cmd_give_resets)

    args = p.parse_args()
    args.func(args)
