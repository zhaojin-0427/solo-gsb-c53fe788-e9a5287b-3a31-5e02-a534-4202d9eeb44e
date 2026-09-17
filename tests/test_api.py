"""End-to-end API tests.

Run against the docker-compose stack (API on $BASE_URL, default
http://localhost:8000).  Each run uses a unique tenant so repeat runs are
safe.  Skipped automatically if the API is unreachable.
"""

import base64
import hashlib
import importlib.util
import os
import time
import uuid

import httpx
import pytest

BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000")
HAVE_TEST_DEPS = importlib.util.find_spec("httpx") is not None

pytestmark = pytest.mark.skipif(not HAVE_TEST_DEPS, reason="httpx not installed")


@pytest.fixture(scope="session")
def client():
    with httpx.Client(base_url=BASE_URL, timeout=10) as c:
        for _ in range(30):
            try:
                r = c.get("/healthz")
                if r.status_code == 200:
                    break
            except httpx.TransportError:
                pass
            time.sleep(1)
        else:
            pytest.skip("API not reachable")
        yield c


@pytest.fixture
def tenant(client):
    tid = "test-" + uuid.uuid4().hex[:16]
    r = client.put(f"/tenants/{tid}")
    assert r.status_code == 201, r.text
    return tid


def _entry(key="k-1", **over):
    body = {
        "idempotency_key": key,
        "claim_type": "add",
        "artifact": {"algorithm": "sha256",
                     "value": hashlib.sha256(key.encode()).hexdigest()},
        "build": {"pipeline": "ci", "commit": "abc", "number": 42},
    }
    body.update(over)
    return body


def test_health(client):
    assert client.get("/healthz").json()["status"] == "ok"


def test_append_and_get_entry(client, tenant):
    r = client.post(f"/tenants/{tenant}/entries", json=_entry())
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["leaf_index"] == 0
    assert data["tree_size"] == 1
    assert data["replayed"] is False
    sth = data["sth"]
    assert sth["tree_size"] == 1
    assert sth["key_id"] == 1

    g = client.get(f"/tenants/{tenant}/entries/0")
    assert g.status_code == 200
    assert g.json()["leaf_hash"] == data["leaf_hash"]


def test_idempotent_same_content_returns_original(client, tenant):
    body = _entry("idem-1")
    r1 = client.post(f"/tenants/{tenant}/entries", json=body)
    r2 = client.post(f"/tenants/{tenant}/entries", json=body)
    assert r1.status_code == r2.status_code == 201
    a, b = r1.json(), r2.json()
    assert a["leaf_index"] == b["leaf_index"] == 0
    assert b["replayed"] is True
    # Same original result (the STH that incorporated the leaf).
    assert a["sth"]["tree_size"] == b["sth"]["tree_size"] == 1
    assert a["sth"]["signature"] == b["sth"]["signature"]
    # No extra leaf created.
    assert client.get(f"/tenants/{tenant}/sth").json()["tree_size"] == 1


def test_same_key_different_content_is_409(client, tenant):
    client.post(f"/tenants/{tenant}/entries", json=_entry("k", build={"v": 1}))
    conflict = _entry("k", build={"v": 2})
    r = client.post(f"/tenants/{tenant}/entries", json=conflict)
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "idempotency_conflict"


def test_concurrent_appends_get_gapless_indices(client, tenant):
    import concurrent.futures

    n = 25
    bodies = [_entry(f"par-{i}") for i in range(n)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(
            lambda b: client.post(f"/tenants/{tenant}/entries", json=b),
            bodies,
        ))
    assert all(r.status_code == 201 for r in results), [r.text for r in results]
    indices = sorted(r.json()["leaf_index"] for r in results)
    assert indices == list(range(n))


def test_inclusion_and_stateless_verify(client, tenant):
    for i in range(6):
        client.post(f"/tenants/{tenant}/entries", json=_entry(f"inc-{i}"))
    sth = client.get(f"/tenants/{tenant}/sth").json()
    size = sth["tree_size"]
    assert size == 6

    for idx in range(size):
        p = client.get(
            f"/tenants/{tenant}/proof/inclusion/{size}",
            params={"leaf_index": idx},
        ).json()
        v = client.post("/verify/inclusion", json={
            "leaf_index": p["leaf_index"],
            "tree_size": p["tree_size"],
            "leaf_hash": p["leaf_hash"],
            "root_hash": p["root_hash"],
            "hashes": p["hashes"],
        })
        assert v.json()["valid"] is True

    # Leaf not yet incorporated in the chosen tree head.
    r = client.get(f"/tenants/{tenant}/proof/inclusion/3", params={"leaf_index": 4})
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "leaf_not_incorporated"


def test_consistency_proofs_verify(client, tenant):
    for i in range(10):
        client.post(f"/tenants/{tenant}/entries", json=_entry(f"con-{i}"))
    for first, second in [(0, 3), (1, 4), (3, 7), (5, 10), (0, 10)]:
        p = client.get(
            f"/tenants/{tenant}/proof/consistency/{first}/{second}"
        ).json()
        v = client.post("/verify/consistency", json={
            "first_tree_size": p["first_tree_size"],
            "second_tree_size": p["second_tree_size"],
            "first_root_hash": p["first_root_hash"],
            "second_root_hash": p["second_root_hash"],
            "hashes": p["hashes"],
        })
        assert v.json()["valid"] is True, (first, second)


def test_sth_signature_and_key_rotation(client, tenant):
    client.post(f"/tenants/{tenant}/entries", json=_entry("rot-0"))
    sth1 = client.get(f"/tenants/{tenant}/sth/1").json()
    keys = client.get(f"/tenants/{tenant}/keys").json()["keys"]
    assert len(keys) == 1

    # Old signature verifies with old key (stateless endpoint).
    v = client.post("/verify/sth", json={
        "tree_id": tenant, "tree_size": sth1["tree_size"],
        "timestamp": sth1["timestamp"], "root_hash": sth1["root_hash"],
        "epoch": sth1["epoch"], "public_key": sth1["public_key"],
        "signature": sth1["signature"],
    })
    assert v.json()["valid"] is True

    # Rotate, append again: new STH signed by new key.
    rot = client.post(f"/tenants/{tenant}/keys/rotate")
    assert rot.status_code == 201
    client.post(f"/tenants/{tenant}/entries", json=_entry("rot-1"))
    sth2 = client.get(f"/tenants/{tenant}/sth/2").json()
    assert sth2["key_id"] == 2
    v2 = client.post("/verify/sth", json={
        "tree_id": tenant, "tree_size": 2,
        "timestamp": sth2["timestamp"], "root_hash": sth2["root_hash"],
        "epoch": sth2["epoch"], "public_key": sth2["public_key"],
        "signature": sth2["signature"],
    })
    assert v2.json()["valid"] is True
    # Old signature still verifies against the retained old key.
    old_key = next(k for k in client.get(f"/tenants/{tenant}/keys").json()["keys"]
                   if k["id"] == 1)["public_key"]
    assert client.post("/verify/sth", json={
        "tree_id": tenant, "tree_size": 1,
        "timestamp": sth1["timestamp"], "root_hash": sth1["root_hash"],
        "epoch": sth1["epoch"], "public_key": old_key,
        "signature": sth1["signature"],
    }).json()["valid"] is True
    # New key does not verify old signature.
    assert client.post("/verify/sth", json={
        "tree_id": tenant, "tree_size": 1,
        "timestamp": sth1["timestamp"], "root_hash": sth1["root_hash"],
        "epoch": sth1["epoch"], "public_key": sth2["public_key"],
        "signature": sth1["signature"],
    }).json()["valid"] is False


def test_revocation_appends_does_not_rewrite(client, tenant):
    client.post(f"/tenants/{tenant}/entries", json=_entry("rev-base"))
    rev = {
        "idempotency_key": "rev-1",
        "claim_type": "revocation",
        "artifact": {"algorithm": "sha256",
                     "value": hashlib.sha256(b"rev").hexdigest()},
        "build": {"reason_ref": "advisory-9"},
        "revokes_leaf_index": 0,
        "reason": "artifact recalled",
    }
    r = client.post(f"/tenants/{tenant}/entries", json=rev)
    assert r.status_code == 201, r.text
    assert r.json()["leaf_index"] == 1
    # Original leaf unchanged.
    e0 = client.get(f"/tenants/{tenant}/entries/0").json()
    assert e0["claim_type"] == "add"
    e1 = client.get(f"/tenants/{tenant}/entries/1").json()
    assert e1["claim_type"] == "revocation"
    # Revoking a nonexistent leaf is an error.
    rev_bad = dict(rev, idempotency_key="rev-bad", revokes_leaf_index=99)
    bad = client.post(f"/tenants/{tenant}/entries", json=rev_bad)
    assert bad.status_code == 422
    assert bad.json()["detail"]["code"] == "revoked_leaf_not_found"


def test_missing_tenant_and_out_of_range(client):
    r = client.get("/tenants/does-not-exist-xyz/sth")
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "tenant_not_found"

    tenant2 = "t2-" + uuid.uuid4().hex[:12]
    client.put(f"/tenants/{tenant2}")
    client.post(f"/tenants/{tenant2}/entries", json=_entry("x"))
    assert client.get(f"/tenants/{tenant2}/entries/9").status_code == 404
    r = client.get(f"/tenants/{tenant2}/proof/inclusion/9")
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "tree_size_unavailable"
