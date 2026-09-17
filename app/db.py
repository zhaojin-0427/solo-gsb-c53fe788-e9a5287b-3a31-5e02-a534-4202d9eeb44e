"""PostgreSQL storage: schema and data-access functions.

Concurrency model for append: every insert takes a row lock on the tenant
(``SELECT ... FOR UPDATE``) inside one transaction, then reads the current
tree size.  Because all appenders for a tenant serialize on that lock and
the new leaf index comes from ``max(index)+1`` under the lock, leaf indices
are gapless, unique and never overwritten.  The transaction also inserts
the signed tree head atomically with the leaf.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

import psycopg
from psycopg.rows import dict_row

from .crypto import generate_keypair

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tenants (
    id            TEXT PRIMARY KEY,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tenant_keys (
    id            BIGINT NOT NULL,
    tenant_id     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    public_key    TEXT NOT NULL,
    private_key   TEXT NOT NULL,
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS leaves (
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    leaf_index      BIGINT NOT NULL,
    idempotency_key TEXT NOT NULL,
    claim_type      TEXT NOT NULL,
    canonical_claim BYTEA NOT NULL,
    leaf_hash       BYTEA NOT NULL,
    incorporated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, leaf_index),
    UNIQUE (tenant_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS tree_heads (
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tree_size   BIGINT NOT NULL,
    timestamp   BIGINT NOT NULL,
    root_hash   BYTEA NOT NULL,
    epoch       BIGINT NOT NULL DEFAULT 0,
    key_id      BIGINT NOT NULL,
    signature   BYTEA NOT NULL,
    PRIMARY KEY (tenant_id, tree_size),
    FOREIGN KEY (tenant_id, key_id) REFERENCES tenant_keys(tenant_id, id)
);
"""


@dataclass
class LeafRow:
    leaf_index: int
    idempotency_key: str
    claim_type: str
    canonical_claim: bytes
    leaf_hash: bytes


@dataclass
class SthRow:
    tree_size: int
    timestamp: int
    root_hash: bytes
    epoch: int
    key_id: int
    signature: bytes


def connect(database_url: str) -> psycopg.Connection:
    conn = psycopg.connect(database_url, row_factory=dict_row, autocommit=False)
    return conn


def init_db(conn: psycopg.Connection) -> None:
    with conn.cursor() as cur:
        cur.execute(SCHEMA_SQL)
    conn.commit()


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def create_tenant(conn: psycopg.Connection, tenant_id: str) -> None:
    """Idempotently create a tenant and seed its first signing key."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO tenants (id) VALUES (%s) ON CONFLICT DO NOTHING",
            (tenant_id,),
        )
        cur.execute("SELECT 1 FROM tenant_keys WHERE tenant_id = %s LIMIT 1", (tenant_id,))
        if cur.fetchone() is None:
            priv_pem, pub_pem = generate_keypair()
            cur.execute(
                "INSERT INTO tenant_keys (tenant_id, id, public_key, private_key, active)"
                " SELECT %s, COALESCE(max(id), 0) + 1, %s, %s, TRUE"
                " FROM tenant_keys WHERE tenant_id = %s",
                (tenant_id, pub_pem, priv_pem, tenant_id),
            )
    conn.commit()


def list_tenants(conn: psycopg.Connection) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT t.id, t.created_at,
                   (SELECT count(*) FROM leaves l WHERE l.tenant_id = t.id) AS tree_size,
                   (SELECT count(*) FROM tenant_keys k WHERE k.tenant_id = t.id) AS key_count
              FROM tenants t ORDER BY t.id
            """
        )
        rows = cur.fetchall()
    for r in rows:
        r["created_at"] = r["created_at"].isoformat()
        r["tree_size"] = int(r["tree_size"])
        r["key_count"] = int(r["key_count"])
    return rows


def list_keys(conn: psycopg.Connection, tenant_id: str) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, public_key, active, created_at"
            " FROM tenant_keys WHERE tenant_id = %s ORDER BY id",
            (tenant_id,),
        )
        rows = cur.fetchall()
    for r in rows:
        r["id"] = int(r["id"])
        r["active"] = bool(r["active"])
        r["created_at"] = r["created_at"].isoformat()
    return rows


def rotate_key(conn: psycopg.Connection, tenant_id: str) -> dict[str, Any]:
    """Deactivate the current key and add a new active one (single tx)."""
    priv_pem, pub_pem = generate_keypair()
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM tenants WHERE id = %s", (tenant_id,))
        if cur.fetchone() is None:
            raise KeyError(tenant_id)
        cur.execute(
            "UPDATE tenant_keys SET active = FALSE WHERE tenant_id = %s AND active",
            (tenant_id,),
        )
        cur.execute(
            "INSERT INTO tenant_keys (tenant_id, id, public_key, private_key, active)"
            " SELECT %s, COALESCE(max(id), 0) + 1, %s, %s, TRUE"
            " FROM tenant_keys WHERE tenant_id = %s RETURNING id",
            (tenant_id, pub_pem, priv_pem, tenant_id),
        )
        new_id = int(cur.fetchone()["id"])
    conn.commit()
    return {"id": new_id, "public_key": pub_pem}


def get_active_key(conn: psycopg.Connection, tenant_id: str) -> dict[str, Any] | None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, public_key, private_key FROM tenant_keys"
            " WHERE tenant_id = %s AND active ORDER BY id DESC LIMIT 1",
            (tenant_id,),
        )
        return cur.fetchone()


def get_key(conn: psycopg.Connection, tenant_id: str, key_id: int) -> dict[str, Any] | None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, public_key, private_key, active FROM tenant_keys"
            " WHERE tenant_id = %s AND id = %s",
            (tenant_id, key_id),
        )
        return cur.fetchone()


def lock_tenant(conn: psycopg.Connection, tenant_id: str) -> bool:
    """Take the per-tenant append lock. Returns False if no such tenant."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id FROM tenants WHERE id = %s FOR UPDATE", (tenant_id,)
        )
        return cur.fetchone() is not None


def lookup_idempotency(conn: psycopg.Connection, tenant_id: str,
                       idempotency_key: str) -> LeafRow | None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT leaf_index, idempotency_key, claim_type, canonical_claim, leaf_hash"
            " FROM leaves WHERE tenant_id = %s AND idempotency_key = %s",
            (tenant_id, idempotency_key),
        )
        row = cur.fetchone()
    return LeafRow(**row) if row else None


def leaf_exists(conn: psycopg.Connection, tenant_id: str, index: int) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM leaves WHERE tenant_id = %s AND leaf_index = %s",
            (tenant_id, index),
        )
        return cur.fetchone() is not None


def insert_leaf(conn: psycopg.Connection, tenant_id: str, idempotency_key: str,
                claim_type: str, canonical_claim: bytes, leaf_hash: bytes) -> int:
    """Insert under the tenant lock; callers must hold it. Returns new index."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT COALESCE(max(leaf_index), -1) + 1 AS next_index"
            " FROM leaves WHERE tenant_id = %s",
            (tenant_id,),
        )
        next_index = int(cur.fetchone()["next_index"])
        cur.execute(
            "INSERT INTO leaves"
            " (tenant_id, leaf_index, idempotency_key, claim_type, canonical_claim, leaf_hash)"
            " VALUES (%s, %s, %s, %s, %s, %s)",
            (tenant_id, next_index, idempotency_key, claim_type,
             canonical_claim, leaf_hash),
        )
    return next_index


def insert_tree_head(conn: psycopg.Connection, tenant_id: str, sth: SthRow) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO tree_heads"
            " (tenant_id, tree_size, timestamp, root_hash, epoch, key_id, signature)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (tenant_id, sth.tree_size, sth.timestamp, sth.root_hash,
             sth.epoch, sth.key_id, sth.signature),
        )


def get_leaf(conn: psycopg.Connection, tenant_id: str, index: int) -> LeafRow | None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT leaf_index, idempotency_key, claim_type, canonical_claim, leaf_hash"
            " FROM leaves WHERE tenant_id = %s AND leaf_index = %s",
            (tenant_id, index),
        )
        row = cur.fetchone()
    return LeafRow(**row) if row else None


def get_leaf_hashes(conn: psycopg.Connection, tenant_id: str,
                    start: int, end: int) -> list[bytes]:
    """Return leaf hashes for indices [start, end)."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT leaf_hash FROM leaves"
            " WHERE tenant_id = %s AND leaf_index >= %s AND leaf_index < %s"
            " ORDER BY leaf_index",
            (tenant_id, start, end),
        )
        return [r["leaf_hash"] for r in cur.fetchall()]


def tree_size(conn: psycopg.Connection, tenant_id: str) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM leaves WHERE tenant_id = %s", (tenant_id,))
        return int(cur.fetchone()["n"])


def get_tree_head(conn: psycopg.Connection, tenant_id: str,
                  tree_size: int) -> SthRow | None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT tree_size, timestamp, root_hash, epoch, key_id, signature"
            " FROM tree_heads WHERE tenant_id = %s AND tree_size = %s",
            (tenant_id, tree_size),
        )
        row = cur.fetchone()
    return SthRow(**row) if row else None
