"""Transparent build-artifact log API.

A per-tenant append-only Merkle log.  Claims are JCS-canonicalized
(RFC 8785), hashed with the RFC 6962 leaf/node domain separation, and
signed per tree head with Ed25519.  The ``/verify/*`` endpoints perform all
checks from the request body alone and never touch the database.
"""

from __future__ import annotations

import os
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Path as PathParam
import psycopg

from . import db, merkle
from .crypto import sign_sth, sth_signing_input, verify_sth
from .jcs import canonicalize, CanonicalizationError
from .schemas import (
    ConsistencyVerifyRequest,
    InclusionVerifyRequest,
    SthVerifyRequest,
    SubmitEntry,
    validate_tenant_id,
)

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://translog:translog@db:5432/translog"
)
STH_EPOCH = int(os.environ.get("STH_EPOCH", "0"))


# ---------------------------------------------------------------------------
# Error type
# ---------------------------------------------------------------------------

class ApiError(HTTPException):
    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(
            status_code=status_code,
            detail={"code": code, "message": message},
        )


# ---------------------------------------------------------------------------
# Lifecycle / DB dependency
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    conn = db.connect(DATABASE_URL)
    db.init_db(conn)
    conn.close()
    yield


app = FastAPI(
    title="Transparent Build Artifact Log",
    version="1.0.0",
    lifespan=lifespan,
)


def get_conn() -> psycopg.Connection:
    conn = db.connect(DATABASE_URL)
    try:
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def build_canonical_claim(payload: SubmitEntry) -> bytes:
    """Assemble the server-controlled claim document and JCS-canonicalize it.

    The canonical claim (not the raw request body) is what gets hashed into
    the leaf, so clients never need to guess field ordering or whitespace.
    """
    claim: dict[str, Any] = {
        "claim_type": payload.claim_type,
        "artifact": {
            "algorithm": payload.artifact.algorithm,
            "value": payload.artifact.value,
        },
        "build": payload.build,
    }
    if payload.claim_type == "revocation":
        claim["revokes_leaf_index"] = payload.revokes_leaf_index
        claim["reason"] = payload.reason
    try:
        return canonicalize(claim)
    except CanonicalizationError as exc:
        raise ApiError(422, "invalid_claim", f"claim cannot be canonicalized: {exc}")


def sth_response(tenant_id: str, sth: db.SthRow, key: dict[str, Any]) -> dict[str, Any]:
    return {
        "tree_id": tenant_id,
        "tree_size": sth.tree_size,
        "timestamp": sth.timestamp,
        "epoch": sth.epoch,
        "root_hash": db.b64e(sth.root_hash),
        "key_id": sth.key_id,
        "signature": db.b64e(sth.signature),
        "public_key": key["public_key"],
    }


def _b64hash(value: str, what: str) -> bytes:
    try:
        raw = db.b64d(value)
    except Exception:
        raise ApiError(422, "invalid_hash", f"{what} must be base64")
    if len(raw) != 32:
        raise ApiError(422, "invalid_hash", f"{what} must be 32 bytes")
    return raw


# ---------------------------------------------------------------------------
# Health / tenants / keys
# ---------------------------------------------------------------------------

@app.get("/healthz")
def healthz(conn=Depends(get_conn)):
    with conn.cursor() as cur:
        cur.execute("SELECT 1")
        cur.fetchone()
    return {"status": "ok"}


@app.get("/tenants", tags=["admin"])
def tenants_list(conn=Depends(get_conn)):
    return {"tenants": db.list_tenants(conn)}


@app.put("/tenants/{tenant_id}", tags=["admin"], status_code=201)
def tenant_create(tenant_id: str = PathParam(...), conn=Depends(get_conn)):
    try:
        validate_tenant_id(tenant_id)
    except ValueError as exc:
        raise ApiError(422, "invalid_tenant", str(exc))
    db.create_tenant(conn, tenant_id)
    return {"tenant_id": tenant_id, "created": True}


@app.get("/tenants/{tenant_id}/keys", tags=["admin"])
def tenant_keys(tenant_id: str = PathParam(...), conn=Depends(get_conn)):
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM tenants WHERE id = %s", (tenant_id,))
        if cur.fetchone() is None:
            raise ApiError(404, "tenant_not_found", f"tenant {tenant_id!r} does not exist")
    return {"tree_id": tenant_id, "keys": db.list_keys(conn, tenant_id)}


@app.post("/tenants/{tenant_id}/keys/rotate", tags=["admin"], status_code=201)
def tenant_rotate_key(tenant_id: str = PathParam(...), conn=Depends(get_conn)):
    try:
        validate_tenant_id(tenant_id)
    except ValueError as exc:
        raise ApiError(422, "invalid_tenant", str(exc))
    try:
        result = db.rotate_key(conn, tenant_id)
    except KeyError:
        raise ApiError(404, "tenant_not_found", f"tenant {tenant_id!r} does not exist")
    return {"tree_id": tenant_id, "new_key_id": result["id"],
            "public_key": result["public_key"]}


# ---------------------------------------------------------------------------
# Append
# ---------------------------------------------------------------------------

@app.post("/tenants/{tenant_id}/entries", status_code=201)
def submit(
    payload: SubmitEntry,
    tenant_id: str = PathParam(...),
    conn=Depends(get_conn),
):
    try:
        validate_tenant_id(tenant_id)
    except ValueError as exc:
        raise ApiError(422, "invalid_tenant", str(exc))

    canonical = build_canonical_claim(payload)
    leaf_h = merkle.leaf_hash(canonical)

    try:
        # Serialize all appenders for this tenant on one transaction.
        if not db.lock_tenant(conn, tenant_id):
            raise ApiError(404, "tenant_not_found",
                           f"tenant {tenant_id!r} does not exist; create it first")

        existing = db.lookup_idempotency(conn, tenant_id, payload.idempotency_key)
        replayed = existing is not None
        if replayed:
            if existing.canonical_claim != canonical:
                raise ApiError(
                    409,
                    "idempotency_conflict",
                    "idempotency key already used with different claim content",
                )
            # The leaf was incorporated when the tree first reached size
            # leaf_index+1; that tree head is the authoritative response.
            incorporated_size = existing.leaf_index + 1
            leaf_index = existing.leaf_index
            size = db.tree_size(conn, tenant_id)
            sth_row = db.get_tree_head(conn, tenant_id, incorporated_size)
            key = db.get_key(conn, tenant_id, sth_row.key_id)
        else:
            if payload.claim_type == "revocation":
                if payload.revokes_leaf_index >= db.tree_size(conn, tenant_id):
                    raise ApiError(
                        422,
                        "revoked_leaf_not_found",
                        "revokes_leaf_index does not exist in the tree",
                    )
            leaf_index = db.insert_leaf(
                conn, tenant_id, payload.idempotency_key,
                payload.claim_type, canonical, leaf_h,
            )
            size = db.tree_size(conn, tenant_id)
            hashes = db.get_leaf_hashes(conn, tenant_id, 0, size)
            root = merkle.tree_root(hashes)
            key = db.get_active_key(conn, tenant_id)
            timestamp_ms = int(time.time() * 1000)
            signing_input = sth_signing_input(
                tenant_id, size, timestamp_ms, root, STH_EPOCH
            )
            signature = sign_sth(key["private_key"], signing_input)
            sth_row = db.SthRow(
                tree_size=size, timestamp=timestamp_ms, root_hash=root,
                epoch=STH_EPOCH, key_id=int(key["id"]), signature=signature,
            )
            db.insert_tree_head(conn, tenant_id, sth_row)

        conn.commit()
    except ApiError:
        conn.rollback()
        raise
    except Exception:
        conn.rollback()
        raise

    return {
        "tree_id": tenant_id,
        "leaf_index": leaf_index,
        "tree_size": size,
        "leaf_hash": db.b64e(leaf_h),
        "canonical_claim": canonical.decode("utf-8"),
        "replayed": replayed,
        "sth": sth_response(tenant_id, sth_row, key),
    }


# ---------------------------------------------------------------------------
# Reads: entries, tree heads, proofs
# ---------------------------------------------------------------------------

@app.get("/tenants/{tenant_id}/entries/{leaf_index}")
def get_entry(
    tenant_id: str = PathParam(...),
    leaf_index: int = PathParam(..., ge=0),
    conn=Depends(get_conn),
):
    leaf = db.get_leaf(conn, tenant_id, leaf_index)
    if leaf is None:
        if db.tree_size(conn, tenant_id) == 0:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM tenants WHERE id = %s", (tenant_id,))
                exists = cur.fetchone() is not None
            if not exists:
                raise ApiError(404, "tenant_not_found",
                               f"tenant {tenant_id!r} does not exist")
        raise ApiError(404, "entry_not_found",
                       f"leaf {leaf_index} does not exist")
    size = db.tree_size(conn, tenant_id)
    return {
        "tree_id": tenant_id,
        "leaf_index": leaf.leaf_index,
        "idempotency_key": leaf.idempotency_key,
        "claim_type": leaf.claim_type,
        "canonical_claim": leaf.canonical_claim.decode("utf-8"),
        "leaf_hash": db.b64e(leaf.leaf_hash),
        "tree_size": size,
    }


@app.get("/tenants/{tenant_id}/sth")
def get_latest_sth(tenant_id: str = PathParam(...), conn=Depends(get_conn)):
    size = db.tree_size(conn, tenant_id)
    if size == 0:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM tenants WHERE id = %s", (tenant_id,))
            if cur.fetchone() is None:
                raise ApiError(404, "tenant_not_found",
                               f"tenant {tenant_id!r} does not exist")
        return {
            "tree_id": tenant_id, "tree_size": 0, "timestamp": 0,
            "epoch": STH_EPOCH, "root_hash": db.b64e(merkle.tree_root([])),
            "key_id": None, "signature": None, "public_key": None,
        }
    sth_row = db.get_tree_head(conn, tenant_id, size)
    key = db.get_key(conn, tenant_id, sth_row.key_id)
    return sth_response(tenant_id, sth_row, key)


@app.get("/tenants/{tenant_id}/sth/{tree_size}")
def get_sth(
    tenant_id: str = PathParam(...),
    tree_size: int = PathParam(..., ge=1),
    conn=Depends(get_conn),
):
    sth_row = db.get_tree_head(conn, tenant_id, tree_size)
    if sth_row is None:
        raise ApiError(404, "tree_head_not_found",
                       f"no tree head for tree_size={tree_size}")
    key = db.get_key(conn, tenant_id, sth_row.key_id)
    return sth_response(tenant_id, sth_row, key)


def _load_sth_for_size(conn, tenant_id: str, tree_size: int) -> db.SthRow:
    sth_row = db.get_tree_head(conn, tenant_id, tree_size)
    if sth_row is None:
        current = db.tree_size(conn, tenant_id)
        if current == 0:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM tenants WHERE id = %s", (tenant_id,))
                if cur.fetchone() is None:
                    raise ApiError(404, "tenant_not_found",
                                   f"tenant {tenant_id!r} does not exist")
        if tree_size > current:
            raise ApiError(400, "tree_size_unavailable",
                           f"tree_size={tree_size} is beyond the current tree ({current})")
        raise ApiError(404, "tree_head_not_found",
                       f"no tree head for tree_size={tree_size}")
    return sth_row


@app.get("/tenants/{tenant_id}/proof/inclusion/{tree_size}")
def inclusion_proof(
    tree_size: int = PathParam(..., ge=1),
    leaf_index: int = 0,
    tenant_id: str = PathParam(...),
    conn=Depends(get_conn),
):
    if leaf_index < 0:
        raise ApiError(422, "invalid_leaf_index", "leaf_index must be >= 0")
    sth_row = _load_sth_for_size(conn, tenant_id, tree_size)
    leaf = db.get_leaf(conn, tenant_id, leaf_index)
    if leaf is None:
        raise ApiError(404, "entry_not_found", f"leaf {leaf_index} does not exist")
    if leaf_index >= tree_size:
        raise ApiError(
            400,
            "leaf_not_incorporated",
            f"leaf {leaf_index} is not incorporated in tree head of size {tree_size}",
        )
    hashes = db.get_leaf_hashes(conn, tenant_id, 0, tree_size)
    path = merkle.inclusion_proof(hashes, leaf_index, tree_size)
    return {
        "tree_id": tenant_id,
        "leaf_index": leaf_index,
        "tree_size": tree_size,
        "leaf_hash": db.b64e(leaf.leaf_hash),
        "root_hash": db.b64e(sth_row.root_hash),
        "hashes": [db.b64e(h) for h in path],
    }


@app.get("/tenants/{tenant_id}/proof/consistency/{first_size}/{second_size}")
def consistency_proof(
    first_size: int = PathParam(...),
    second_size: int = PathParam(...),
    tenant_id: str = PathParam(...),
    conn=Depends(get_conn),
):
    if first_size < 0 or second_size < 1:
        raise ApiError(422, "invalid_tree_size", "tree sizes must be non-negative")
    if first_size > second_size:
        raise ApiError(422, "invalid_tree_size",
                       "first size must be <= second size")

    sth2 = _load_sth_for_size(conn, tenant_id, second_size)
    if first_size == 0:
        empty_root = merkle.tree_root([])
        return {
            "tree_id": tenant_id,
            "first_tree_size": 0,
            "second_tree_size": second_size,
            "first_root_hash": db.b64e(empty_root),
            "second_root_hash": db.b64e(sth2.root_hash),
            "hashes": [],
        }

    sth1 = _load_sth_for_size(conn, tenant_id, first_size)
    hashes = db.get_leaf_hashes(conn, tenant_id, 0, second_size)
    proof = merkle.consistency_proof(hashes, first_size, second_size)
    return {
        "tree_id": tenant_id,
        "first_tree_size": first_size,
        "second_tree_size": second_size,
        "first_root_hash": db.b64e(sth1.root_hash),
        "second_root_hash": db.b64e(sth2.root_hash),
        "hashes": [db.b64e(h) for h in proof],
    }


# ---------------------------------------------------------------------------
# Stateless verification (NO database access)
# ---------------------------------------------------------------------------

@app.post("/verify/inclusion", tags=["verify"])
def verify_inclusion_endpoint(req: InclusionVerifyRequest):
    leaf = _b64hash(req.leaf_hash, "leaf_hash")
    root = _b64hash(req.root_hash, "root_hash")
    path = [_b64hash(h, "hash") for h in req.hashes]
    ok = merkle.verify_inclusion(
        req.leaf_index, req.tree_size, leaf, path, root
    )
    return {"valid": ok}


@app.post("/verify/consistency", tags=["verify"])
def verify_consistency_endpoint(req: ConsistencyVerifyRequest):
    root1 = _b64hash(req.first_root_hash, "first_root_hash")
    root2 = _b64hash(req.second_root_hash, "second_root_hash")
    hashes = [_b64hash(h, "hash") for h in req.hashes]
    ok = merkle.verify_consistency(
        req.first_tree_size, req.second_tree_size, hashes, root1, root2
    )
    return {"valid": ok}


@app.post("/verify/sth", tags=["verify"])
def verify_sth_endpoint(req: SthVerifyRequest):
    root = _b64hash(req.root_hash, "root_hash")
    try:
        signature = db.b64d(req.signature)
    except Exception:
        raise ApiError(422, "invalid_signature", "signature must be base64")
    signing_input = sth_signing_input(
        req.tree_id, req.tree_size, req.timestamp, root, req.epoch
    )
    ok = verify_sth(req.public_key, signing_input, signature)
    return {"valid": ok}
