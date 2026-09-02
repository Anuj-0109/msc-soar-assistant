import sqlite3

from werkzeug.security import generate_password_hash

from settings import (
    DEFAULT_ADMIN_PASSWORD,
    DEFAULT_ADMIN_USERNAME,
)


DATABASE_NAME = "soar_platform.db"


def get_db_connection():
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_expanded_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # 1. Users table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT CHECK(
                    role IN ('admin', 'analyst', 'readonly')
                ) DEFAULT 'analyst',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

        # Create an administrator only when the database has no users
        # and a password is configured in .env.
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]

        if user_count == 0 and DEFAULT_ADMIN_PASSWORD:
            password_hash = generate_password_hash(
                DEFAULT_ADMIN_PASSWORD
            )

            cursor.execute(
                """
                INSERT INTO users (
                    username,
                    password_hash,
                    role
                )
                VALUES (?, ?, 'admin')
                """,
                (
                    DEFAULT_ADMIN_USERNAME,
                    password_hash,
                ),
            )

        # 2. Incidents table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                ioc_value TEXT,
                ioc_type TEXT,
                severity TEXT CHECK(
                    severity IN (
                        'CRITICAL',
                        'HIGH',
                        'MEDIUM',
                        'LOW',
                        'INFORMATIONAL'
                    )
                ),
                risk_score INTEGER DEFAULT 0,
                status TEXT CHECK(
                    status IN (
                        'OPEN',
                        'INVESTIGATING',
                        'CONTAINED',
                        'CLOSED'
                    )
                ) DEFAULT 'OPEN',
                assigned_analyst TEXT DEFAULT 'UNASSIGNED',
                mitre_tactic TEXT DEFAULT 'N/A',
                mitre_technique TEXT DEFAULT 'N/A',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

        # Safe schema migrations
        cursor.execute("PRAGMA table_info(incidents);")
        columns = [row[1] for row in cursor.fetchall()]

        if "mitre_tactic" not in columns:
            cursor.execute(
                """
                ALTER TABLE incidents
                ADD COLUMN mitre_tactic TEXT DEFAULT 'N/A';
                """
            )

        if "mitre_technique" not in columns:
            cursor.execute(
                """
                ALTER TABLE incidents
                ADD COLUMN mitre_technique TEXT DEFAULT 'N/A';
                """
            )

        # 3. Timeline events
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS timeline_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                action_by TEXT NOT NULL,
                action_description TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(incident_id)
                    REFERENCES incidents(id)
                    ON DELETE CASCADE
            );
            """
        )

        # 4. Comments
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                author TEXT NOT NULL,
                comment_text TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(incident_id)
                    REFERENCES incidents(id)
                    ON DELETE CASCADE
            );
            """
        )

        # 5. Playbooks
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS playbooks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                trigger_condition TEXT NOT NULL,
                action_type TEXT NOT NULL,
                enabled INTEGER DEFAULT 1
            );
            """
        )

        # 6. Playbook executions
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS playbook_executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                playbook_id INTEGER NOT NULL,
                incident_id INTEGER NOT NULL,
                executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT CHECK(
                    status IN ('SUCCESS', 'FAILED', 'PENDING')
                ),
                output_log TEXT,
                FOREIGN KEY(playbook_id)
                    REFERENCES playbooks(id),
                FOREIGN KEY(incident_id)
                    REFERENCES incidents(id)
                    ON DELETE CASCADE
            );
            """
        )

        # Seed the default playbook
        cursor.execute("SELECT COUNT(*) FROM playbooks")
        playbook_count = cursor.fetchone()[0]

        if playbook_count == 0:
            cursor.execute(
                """
                INSERT INTO playbooks (
                    name,
                    trigger_condition,
                    action_type,
                    enabled
                )
                VALUES (?, ?, ?, 1)
                """,
                (
                    "Auto-Block Critical IOCs",
                    "severity == 'CRITICAL'",
                    "KERNEL_BLOCK",
                ),
            )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()
