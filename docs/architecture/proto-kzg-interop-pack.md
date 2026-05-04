# Proto KZG interop pack

Date: 2026-05-04

## Scope

This document freezes the proto contract for ShareProof and DataAvailabilityHeader, pins a revision hash, and defines interop expectations. It also specifies golden vectors and validation expectations for consumers.

Reference design: docs/architecture/proto-kzg-design-and-interoperability.md

In scope:

- proto/celestia/core/v1/proof/proof.proto
- proto/celestia/core/v1/da/data_availability_header.proto

## Proto revision pin

- Repo: celestia-app
- Commit hash: c1ccf1b994dd0e3e3302cdb747e5ca53b499587e
- Required for: ShareProof and DataAvailabilityHeader wire compatibility

## Proto summary (wire shape)

ShareProof:

- data: repeated bytes
- share_proofs: repeated KZGMultiProof (proof: bytes)
- namespace_id: bytes
- commitment_proof: CommitmentProof
- namespace_version: uint32

CommitmentProof:

- column_proofs: repeated KZGMultiProof (proof: bytes)
- column_indices: repeated uint32
- root_commitment: bytes (optional)

DataAvailabilityHeader:

- row_roots: repeated bytes (deprecated)
- column_roots: repeated bytes (deprecated)
- piece_commitments: repeated bytes
- column_commitments: repeated bytes
- namespace_index: repeated NamespaceRangeEntry

NamespaceRangeEntry:

- namespace_id: bytes
- start: uint32
- end: uint32

## Descriptor set

Status: not committed in this repo.

If needed by partner tooling, generate a descriptor set using the pinned commit and share it alongside proto files. Example command (not executed here):

- protoc --proto_path=proto --include_imports --descriptor_set_out=celestia-core-v1.desc \
  proto/celestia/core/v1/proof/proof.proto \
  proto/celestia/core/v1/da/data_availability_header.proto

## Golden vectors (binary payload) and validation expectations

Status: vectors are committed under docs/architecture/testdata/proto-kzg/.

Required vectors (binary protobuf Marshal output) and expected validation results:

ShareProof vectors:

- share_proof_valid.bin: expected validate pass
- share_proof_empty_share_proofs.bin: expected validate fail (share_proofs empty)
- share_proof_empty_kzg_proof.bin: expected validate fail (KZGMultiProof.proof empty)
- share_proof_missing_commitment_proof.bin: expected validate fail (commitment_proof nil)
- share_proof_mismatched_column_counts.bin: expected validate fail (column_proofs != column_indices)
- share_proof_root_mismatch.bin: expected validate fail (root_commitment mismatch when root provided)

DataAvailabilityHeader vectors:

- dah_valid_new_fields.bin: expected shape pass (see expected results doc for ValidateBasic behavior)

Vectors and expected results:

- docs/architecture/testdata/proto-kzg/
- docs/architecture/testdata/proto-kzg/expected_results.md

Consumers must treat these vectors as canonical for the pinned commit.

## Validation rules (consumer behavior)

ShareProof consumer must reject payloads that violate any of the following:

- share_proofs is empty
- any KZGMultiProof.proof is empty
- commitment_proof is missing
- commitment_proof.column_proofs is empty
- commitment_proof.column_proofs length != commitment_proof.column_indices length
- commitment_proof.root_commitment is present but does not match provided root
- cryptographic verification fails (if full context available)

DataAvailabilityHeader consumer must:

- prefer piece_commitments, column_commitments, namespace_index when present
- allow deprecated fields only for backward compatibility
- reject headers that fail ValidateBasic

## Version matrix and interop expectations

Definitions:

- old: pre-KZG-first proof schema (row-based wire shape)
- new: KZG-first schema in this commit

Interop matrix:

- new -> new: must pass
- new -> old: expected fail for ShareProof (schema mismatch); DAH may parse but new fields ignored
- old -> new: expected fail for ShareProof (missing new fields); DAH should pass only if legacy fields are still populated

Implication for core rollout:

- If any old consumers exist, core should run dual-mode (emit old proof schema + new) or schedule a hard break.
- If no old consumers exist, core can hard break to KZG-first wire format.

## RPC / JSON payload contract

No RPC services are defined in the proof/DAH protos. No JSON payload changes were identified in scope. If any JSON transport wraps ShareProof or DataAvailabilityHeader, ensure:

- bytes fields are base64 in JSON
- repeated bytes are arrays of base64 strings
- validation errors map to clear client errors (see release notes)

## Checklist for partner teams

- Pin to commit hash above for codegen
- Confirm ShareProof and DAH match the wire shape in this doc
- Exchange descriptor set only if tooling needs it
- Validate against golden vectors once available
- Confirm interop plan (dual-mode or hard break)
