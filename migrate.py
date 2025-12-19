import sqlite3
from pathlib import Path

DB = Path(__file__).with_name("reservations.sqlite3")

def col_exists(cur, table, col):
    cur.execute(f"PRAGMA table_info({table});")
    return any(r[1] == col for r in cur.fetchall())

def ensure_column(cur, table, col, ddl):
    if not col_exists(cur, table, col):
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl};")
        print(f"OK: added {table}.{col}")
    else:
        print(f"SKIP: {table}.{col} exists")

def main():
    if not DB.exists():
        raise SystemExit(f"DB not found: {DB}")

    con = sqlite3.connect(DB)
    try:
        cur = con.cursor()

        # Users: profil brigádníka
        ensure_column(cur, "users", "email", "VARCHAR(240)")
        ensure_column(cur, "users", "full_name", "VARCHAR(240)")
        ensure_column(cur, "users", "phone", "VARCHAR(80)")

        # Signups: evidence hodin na akci
        ensure_column(cur, "reservation_signups", "minutes", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(cur, "reservation_signups", "note", "TEXT")

        con.commit()
        print("DONE: migration finished")
    finally:
        con.close()

if __name__ == "__main__":
    main()
