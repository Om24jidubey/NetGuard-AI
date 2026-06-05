import sqlite3

DB_NAME = "netguard.db"


def init_db():

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,

        attack_type TEXT,

        severity TEXT,

        score REAL,

        source_ip TEXT
    )
    """)

    conn.commit()
    conn.close()

def save_alert(
    attack_type,
    severity,
    score,
    source_ip
):

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO alerts
    (
        attack_type,
        severity,
        score,
        source_ip
    )
    VALUES (?, ?, ?, ?)
    """, (
        attack_type,
        severity,
        score,
        source_ip
    ))

    conn.commit()
    conn.close()

def get_alert_history():

    conn = sqlite3.connect(DB_NAME)

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM alerts
    ORDER BY timestamp DESC
    LIMIT 100
    """)

    rows = cursor.fetchall()

    conn.close()

    return [
        dict(row)
        for row in rows
    ]
