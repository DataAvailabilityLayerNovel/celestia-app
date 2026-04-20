# Proto Design (KZG-first) and Interoperability Simulation

## 1. Scope

This document describes the new proto design after migrating proof flow to KZG-first and adding extended DAH fields.

Files in scope:
- `proto/celestia/core/v1/proof/proof.proto`
- `proto/celestia/core/v1/da/data_availability_header.proto`

## 2. Design Goals

- Keep proof schema focused on KZG semantics.
- Remove legacy row-based proof shape from wire schema for proof exchange.
- Keep DAH extensible for current commitment model.
- Make interop testing reproducible between this repo and external consumers.

## 3. New Proto Design

### 3.1 Proof Schema (KZG-first)

`ShareProof` now carries:
- `data`
- `share_proofs` as `repeated KZGMultiProof`
- `namespace_id`
- `commitment_proof` as `CommitmentProof`
- `namespace_version`

`KZGMultiProof` carries:
- `proof` (bytes)

`CommitmentProof` carries:
- `column_proofs` as `repeated KZGMultiProof`
- `column_indices` as `repeated uint32`
- `root_commitment` (bytes)

Legacy `RowProof`, `NMTProof`, and old row-based wire fields are not part of `proof.proto` anymore.

### 3.2 DataAvailabilityHeader Schema

`DataAvailabilityHeader` keeps legacy fields but marks them deprecated and adds new fields:
- `row_roots` (deprecated)
- `column_roots` (deprecated)
- `piece_commitments`
- `column_commitments`
- `namespace_index` as `repeated NamespaceRangeEntry`

`NamespaceRangeEntry` carries:
- `namespace_id`
- `start`
- `end`

## 4. Wire Contract and Validation Rules

### 4.1 ShareProof minimum contract

Producer should ensure:
- `share_proofs` is non-empty.
- each `KZGMultiProof.proof` is non-empty.
- `commitment_proof` is present.
- `len(column_proofs) == len(column_indices)`.
- if `root_commitment` is provided, it should match verifier root input.

Consumer should reject payload when any rule above is violated.

### 4.2 DAH contract

Producer should fill new fields (`piece_commitments`, `column_commitments`, `namespace_index`) for new integrations.

Consumer strategy:
- Prefer new fields when present.
- Read deprecated fields only for temporary backward compatibility.

## 5. Interoperability Simulation with External Parties

Yes, there are several practical ways to simulate proto exchange with other systems.

### Method A: Binary roundtrip (closest to real wire)

Use one side as producer and another side as consumer.

Producer side:
1. Build message instance in Go.
2. Serialize with protobuf (`Marshal`).
3. Save binary payload to file.

Consumer side:
1. Load the same binary file.
2. Deserialize (`Unmarshal`) using generated code from the same `.proto`.
3. Run semantic validation rules.

What this catches:
- Field number/type mismatch.
- Missing required semantic fields.
- Byte-level incompatibility.

### Method B: Descriptor + grpcurl/protoc tooling

Generate descriptors and inspect payload shape without app runtime.

Recommended flow:
1. Generate code and descriptors.
2. Use grpcurl (or protoc with decode options) to send/inspect JSON and binary forms.
3. Verify external side can parse all fields.

What this catches:
- Schema drift between teams.
- JSON mapping issues for bytes/repeated fields.

### Method C: Golden vectors (best for CI)

Create a `testdata` folder with:
- valid share proof binary payload
- invalid payload variants (empty proofs, mismatched columns, wrong root)
- DAH payload with new fields populated

Then run consumer tests on every CI run.

What this catches:
- Regressions after proto or validator changes.
- Behavior drift in edge cases.

### Method D: Version matrix simulation

Run matrix tests for producer/consumer versions:
- new producer -> new consumer (must pass)
- new producer -> old consumer (define expected behavior)
- old producer -> new consumer (only if compatibility is still required)

What this catches:
- Upgrade sequencing risk.
- Operational rollout issues.

## 6. Suggested Local Playbook (this repo)

1. Regenerate protobuf artifacts:

```bash
make proto-gen
```

2. Build application:

```bash
make build
```

3. Run proof package tests:

```bash
go test ./pkg/proof/...
```

4. For cross-team simulation, exchange:
- `.proto` files in scope
- generated descriptor set (if used)
- golden payload files and expected validation result

## 7. Exchange Checklist for Partner Teams

- Confirm exact proto revision hash.
- Confirm `proof.proto` is KZG-first version.
- Confirm deprecated DAH fields are not relied on for new logic.
- Confirm bytes fields are transported unchanged.
- Confirm semantic validation result for agreed golden vectors.

## 8. Rollout Guidance

- Phase 1: run dual validation in staging using golden vectors.
- Phase 2: enable KZG-only proof exchange in production paths.
- Phase 3: remove any leftover legacy runtime code when no consumers require it.

## 9. Risks

- External clients still expecting row-based proof wire schema.
- Inconsistent handling of bytes encoding in JSON transport.
- Missing negative test vectors for malformed commitment proofs.

## 10. Decision Summary

- Proof wire schema is KZG-first.
- DAH schema is extended with commitment-oriented fields.
- Interop should be validated by binary roundtrip + golden vectors + version matrix tests.
