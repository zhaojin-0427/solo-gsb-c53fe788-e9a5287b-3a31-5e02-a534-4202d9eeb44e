"""RFC 6962 style Merkle hashing, inclusion and consistency proofs.

Leaves are hash inputs prefixed with ``\\x00`` and internal nodes with
``\\x01`` ("leaf hash" / "node hash" separation from RFC 6962 section 2.1).

Hash storage everywhere uses raw 32-byte SHA-256 digests; the HTTP layer
base64-encodes them.

Consistency proofs follow the RFC 6962/9162 wire convention: when the old
tree size is a power of two (and smaller than the new size), the first
element of the proof is the old Merkle root hash itself.  Inclusion proofs
need no such convention.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence

LEAF_HASH_PREFIX = b"\x00"
NODE_HASH_PREFIX = b"\x01"


class ProofError(ValueError):
    """Raised when a proof is malformed or does not verify."""


HashFn = Callable[[bytes], bytes]


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(leaf_data: bytes, hash_fn: HashFn = _sha256) -> bytes:
    """RFC 6962 leaf hash: H(0x00 || leaf_data)."""
    return hash_fn(LEAF_HASH_PREFIX + leaf_data)


def node_hash(left: bytes, right: bytes, hash_fn: HashFn = _sha256) -> bytes:
    """RFC 6962 node hash: H(0x01 || left || right)."""
    return hash_fn(NODE_HASH_PREFIX + left + right)


def _largest_power_of_two_less_than(n: int) -> int:
    """Largest power of two strictly less than n (RFC 6962's k)."""
    if n < 2:
        raise ValueError(f"need n >= 2, got {n}")
    return 1 << ((n - 1).bit_length() - 1)


def subtree_hash(leaves: Sequence[bytes], start: int, size: int,
                 hash_fn: HashFn = _sha256) -> bytes:
    """Root hash of the virtual subtree covering leaves[start:start+size]."""
    if size == 1:
        return leaves[start]
    k = _largest_power_of_two_less_than(size)
    return node_hash(
        subtree_hash(leaves, start, k, hash_fn),
        subtree_hash(leaves, start + k, size - k, hash_fn),
        hash_fn,
    )


def tree_root(leaves: Sequence[bytes], hash_fn: HashFn = _sha256) -> bytes:
    """Root hash of a whole tree; empty tree hashes as SHA-256 of empty."""
    if not leaves:
        return hash_fn(b"")
    return subtree_hash(leaves, 0, len(leaves), hash_fn)


def inclusion_proof(leaves: Sequence[bytes], leaf_index: int,
                    tree_size: int | None = None,
                    hash_fn: HashFn = _sha256) -> list[bytes]:
    """Audit path for leaf *leaf_index* in a tree of *tree_size* leaves.

    Implements RFC 6962 §2.1.1 (PATH).  The leaf must already be
    incorporated in *tree_size*.
    """
    n = len(leaves) if tree_size is None else tree_size
    m = leaf_index
    if n <= 0 or m < 0 or m >= n or n > len(leaves):
        raise ProofError("leaf index out of range for the given tree size")

    proof: list[bytes] = []

    def path(start: int, size: int, index: int) -> None:
        if size == 1:
            return
        k = _largest_power_of_two_less_than(size)
        if index < k:
            path(start, k, index)
            proof.append(subtree_hash(leaves, start + k, size - k, hash_fn))
        else:
            path(start + k, size - k, index - k)
            proof.append(subtree_hash(leaves, start, k, hash_fn))

    path(0, n, m)
    return proof


def verify_inclusion(leaf_index: int, tree_size: int, leaf_data_hash: bytes,
                     proof: Sequence[bytes], root_hash: bytes,
                     hash_fn: HashFn = _sha256) -> bool:
    """Verify an RFC 6962/9162 appendix-C.1 inclusion proof."""
    if tree_size <= 0 or leaf_index < 0 or leaf_index >= tree_size:
        return False

    fn = leaf_index
    sn = tree_size - 1
    r = leaf_data_hash
    for p in proof:
        if sn == 0:
            return False  # proof contains nodes past the root
        if fn & 1 or fn == sn:
            r = node_hash(p, r, hash_fn)
        else:
            r = node_hash(r, p, hash_fn)
        fn >>= 1
        sn >>= 1
    return r == root_hash


def consistency_proof(leaves: Sequence[bytes], first: int, second: int,
                      hash_fn: HashFn = _sha256) -> list[bytes]:
    """Consistency proof between tree sizes *first* and *second*.

    ``0 <= first < second``.  The proof is the ordered list of complete
    subtree hashes emitted by a mirrored recursion of the tree: at every
    split it includes the sibling subtree that the verifier cannot derive
    from the shared prefix, plus the common-base subtree at the recursion
    base.  For *first* a power of two the first emitted hash is the old
    tree root itself, matching the RFC 6962 wire convention.  Leaf/node
    domain separation (0x00/0x01 prefixes) follows RFC 6962.
    """
    if first < 0 or second < 0 or first >= second or second > len(leaves):
        raise ProofError("invalid tree sizes for consistency proof")
    if first == 0:
        return []

    nodes: list[bytes] = []

    def subproof(m: int, n: int, offset: int) -> None:
        if m == n:
            # Common-base subtree; the verifier cannot compute its hash.
            nodes.append(subtree_hash(leaves, offset, n, hash_fn))
            return
        k = _largest_power_of_two_less_than(n)
        if m <= k:
            subproof(m, k, offset)
            nodes.append(subtree_hash(leaves, offset + k, n - k, hash_fn))
        else:
            subproof(m - k, n - k, offset + k)
            nodes.append(subtree_hash(leaves, offset, k, hash_fn))

    subproof(first, second, 0)
    return nodes


def verify_consistency(first: int, second: int, proof: Sequence[bytes],
                       first_root: bytes, second_root: bytes,
                       hash_fn: HashFn = _sha256) -> bool:
    """Verify a consistency proof produced by :func:`consistency_proof`.

    Mirrors the generator: it reconstructs the old and new subtree roots
    at every split, consuming the same hashes in the same order.  No
    database access is required.
    """
    if first < 0 or second < 0 or first > second:
        return False
    if first == second:
        return not proof and first_root == second_root
    if first == 0:
        # The empty tree is a prefix of every tree; proof must be empty.
        return not proof
    if not proof:
        return False

    nodes = iter(proof)

    def take() -> bytes:
        try:
            return next(nodes)
        except StopIteration:
            raise ProofError("proof too short")

    def verify(m: int, n: int) -> tuple[bytes, bytes]:
        """Return (old-restricted root, new subtree root) at this split."""
        if m == n:
            b = take()
            return b, b
        k = _largest_power_of_two_less_than(n)
        if m <= k:
            a, d = verify(m, k)
            b = take()  # new-only right subtree
            return a, node_hash(d, b, hash_fn)
        a, d = verify(m - k, n - k)
        b = take()  # complete left subtree
        return node_hash(b, a, hash_fn), node_hash(b, d, hash_fn)

    try:
        old_root, new_root = verify(first, second)
    except ProofError:
        return False

    # The proof must be consumed exactly; extra nodes are invalid.
    if next(nodes, None) is not None:
        return False
    return old_root == first_root and new_root == second_root
