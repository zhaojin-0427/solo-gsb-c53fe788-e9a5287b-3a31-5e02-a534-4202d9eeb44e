"""Pydantic models for HTTP request and response bodies."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9._-]{1,200}$")
_TENANT_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
_SUPPORTED_DIGESTS = {"sha256": 64, "sha384": 96, "sha512": 128}
_HEX_RE = re.compile(r"^[0-9a-f]+$")


def validate_tenant_id(value: str) -> str:
    if not _TENANT_RE.match(value):
        raise ValueError(
            "tenant must be 1-64 chars: lowercase letters, digits or dashes"
        )
    return value


def validate_idempotency_key(value: str) -> str:
    if not _IDEMPOTENCY_RE.match(value):
        raise ValueError(
            "idempotency key must be 1-200 chars of [A-Za-z0-9._-]"
        )
    return value


class ArtifactDigest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    algorithm: Literal["sha256", "sha384", "sha512"]
    value: str = Field(..., description="lowercase hex digest of the artifact")

    @field_validator("value")
    @classmethod
    def _hex(cls, v: str, info) -> str:
        algo = info.data.get("algorithm", "sha256")
        if not _HEX_RE.match(v) or len(v) != _SUPPORTED_DIGESTS[algo]:
            raise ValueError(f"digest must be {_SUPPORTED_DIGESTS[algo]} lowercase hex chars")
        return v


class SubmitEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idempotency_key: str
    claim_type: Literal["add", "revocation"]
    artifact: ArtifactDigest
    build: dict[str, Any] = Field(
        ..., description="arbitrary build metadata (pipeline id, commit, builder, ...)"
    )
    # Required for claim_type=revocation; the leaf being revoked must exist.
    revokes_leaf_index: int | None = Field(default=None, ge=0)
    reason: str | None = Field(default=None, max_length=2000)

    @field_validator("idempotency_key")
    @classmethod
    def _idem(cls, v: str) -> str:
        return validate_idempotency_key(v)

    @model_validator(mode="after")
    def _revocation_fields(self) -> "SubmitEntry":
        if self.claim_type == "revocation":
            if self.revokes_leaf_index is None:
                raise ValueError("revocation claims require revokes_leaf_index")
        else:
            if self.revokes_leaf_index is not None or self.reason is not None:
                raise ValueError("revokes_leaf_index/reason only valid for revocation claims")
        return self


class InclusionVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    leaf_index: int = Field(ge=0)
    tree_size: int = Field(ge=1)
    leaf_hash: str = Field(..., description="base64 leaf hash H(0x00 || canonical claim)")
    root_hash: str = Field(..., description="base64 expected tree root hash")
    hashes: list[str] = Field(..., description="base64 audit path")


class ConsistencyVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    first_tree_size: int = Field(ge=0)
    second_tree_size: int = Field(ge=0)
    first_root_hash: str
    second_root_hash: str
    hashes: list[str]

    @model_validator(mode="after")
    def _order(self) -> "ConsistencyVerifyRequest":
        if self.first_tree_size > self.second_tree_size:
            raise ValueError("first_tree_size must be <= second_tree_size")
        return self


class SthVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tree_id: str
    tree_size: int = Field(ge=0)
    timestamp: int = Field(ge=0)
    root_hash: str
    epoch: int = Field(ge=0)
    public_key: str = Field(..., description="PEM Ed25519 public key")
    signature: str = Field(..., description="base64 Ed25519 signature")
