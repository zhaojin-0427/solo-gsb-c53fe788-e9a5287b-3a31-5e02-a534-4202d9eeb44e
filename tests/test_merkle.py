import hashlib
import random

import pytest

from app import merkle as M

H = lambda d: hashlib.sha256(d).digest()

N = 200
LEAVES = [M.leaf_hash(f"leaf-{i}".encode()) for i in range(N)]
ROOTS = {0: H(b"")}
for n in range(1, N):
    ROOTS[n] = M.subtree_hash(LEAVES, 0, n)


def test_empty_tree_root():
    assert M.tree_root([]) == H(b"")


def test_leaf_prefix_is_zero_byte():
    assert M.leaf_hash(b"x") == H(b"\x00x")
    assert M.node_hash(b"a", b"b") == H(b"\x01ab")


def test_all_inclusion_proofs_verify():
    for size in range(1, N):
        for idx in range(size):
            proof = M.inclusion_proof(LEAVES, idx, size)
            assert M.verify_inclusion(idx, size, LEAVES[idx], proof, ROOTS[size])


def test_inclusion_proof_rejects_tampering():
    random.seed(11)
    for _ in range(300):
        size = random.randint(2, N - 1)
        idx = random.randrange(size)
        proof = M.inclusion_proof(LEAVES, idx, size)
        mutated = list(proof)
        mutated[random.randrange(len(mutated))] = H(b"tamper")
        assert not M.verify_inclusion(idx, size, LEAVES[idx], mutated, ROOTS[size])
        assert not M.verify_inclusion(idx, size, LEAVES[idx], proof[:-1], ROOTS[size])
        assert not M.verify_inclusion(
            (idx + 1) % size, size, LEAVES[idx], proof, ROOTS[size]
        )


def test_inclusion_range_errors():
    with pytest.raises(M.ProofError):
        M.inclusion_proof(LEAVES, 5, 5)
    with pytest.raises(M.ProofError):
        M.inclusion_proof(LEAVES, -1, 5)

def test_all_consistency_proofs_verify():
    for second in range(1, N):
        for first in range(0, second):
            proof = M.consistency_proof(LEAVES, first, second)
            assert M.verify_consistency(
                first, second, proof, ROOTS[first], ROOTS[second]
            ), (first, second)


def test_consistency_edge_cases():
    proof = M.consistency_proof(LEAVES, 0, 7)
    assert proof == []
    assert M.verify_consistency(0, 7, [], ROOTS[0], ROOTS[7])
    assert M.verify_consistency(7, 7, [], ROOTS[7], ROOTS[7])
    assert not M.verify_consistency(7, 7, [H(b"x")], ROOTS[7], ROOTS[7])


def test_consistency_rejects_tampering():
    random.seed(23)
    for _ in range(500):
        second = random.randint(2, N - 1)
        first = random.randint(1, second - 1)
        proof = M.consistency_proof(LEAVES, first, second)
        mutated = list(proof)
        mutated[random.randrange(len(mutated))] = H(b"tamper")
        assert not M.verify_consistency(
            first, second, mutated, ROOTS[first], ROOTS[second]
        )
        assert not M.verify_consistency(
            first, second, proof[:-1], ROOTS[first], ROOTS[second]
        )
        assert not M.verify_consistency(
            first, second, proof + [H(b"extra")], ROOTS[first], ROOTS[second]
        )
        other = random.choice([s for s in range(1, N) if s != second])
        assert not M.verify_consistency(
            first, second, proof, ROOTS[first], ROOTS[other]
        )


def test_consistency_is_chained():
    # Proof f->s composed with s->t roots: all three heads stay consistent.
    for f, s, t in [(1, 3, 7), (2, 5, 13), (3, 4, 9), (100, 150, 199)]:
        p1 = M.consistency_proof(LEAVES, f, s)
        p2 = M.consistency_proof(LEAVES, s, t)
        assert M.verify_consistency(f, s, p1, ROOTS[f], ROOTS[s])
        assert M.verify_consistency(s, t, p2, ROOTS[s], ROOTS[t])
