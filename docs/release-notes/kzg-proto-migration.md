# Migration note: KZG-first proof proto and DAH extensions

Date: 2026-05-04

## Summary

This release freezes the ShareProof and DataAvailabilityHeader proto contract for KZG-first proof exchange and adds DAH extension fields. It also deprecates row-based proof wire shapes for interop.

## What changed

- ShareProof is KZG-first and no longer carries legacy row-based proof fields.
- DataAvailabilityHeader adds piece_commitments, column_commitments, and namespace_index fields.
- row_roots and column_roots are deprecated and intended only for temporary compatibility.

## Compatibility

- New producer -> new consumer: supported
- New producer -> old consumer: ShareProof expected to fail parse; DAH may parse but ignores new fields
- Old producer -> new consumer: ShareProof expected to fail parse; DAH may parse if legacy fields remain populated

If any old consumers exist, run dual-mode proof exchange or plan a hard break.

## Consumer expectations

- ShareProof validation must enforce non-empty proofs, non-nil commitment_proof, and matching column counts.
- DAH validation must enforce a valid commitment root and minimal commitment count.

## JSON / RPC behavior

No RPC services are defined in the proof/DAH protos. If JSON transport wraps these messages:

- bytes fields must be base64
- repeated bytes are arrays of base64 strings
- validation failures should return explicit errors for missing/empty proofs and root mismatch

## Action items for integrators

- Regenerate code from the pinned commit hash
- Update decoders to the KZG-first ShareProof wire shape
- Ensure DAH consumers prefer new fields and fall back to deprecated fields only if required
- Validate with golden vectors once published

## Rollout suggestion

- Stage 1: enable dual-mode validation (if needed) and run interop tests
- Stage 2: require KZG-first proofs in production
- Stage 3: remove legacy proof handling once all consumers are updated
