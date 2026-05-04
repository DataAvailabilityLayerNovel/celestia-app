# Proto KZG golden vectors - expected results

Scope: structural and schema-level validation only. All bytes are dummy placeholders.

Unless stated otherwise, "validate" below means:
- ShareProof: structural checks in docs/architecture/proto-kzg-design-and-interoperability.md
- DataAvailabilityHeader: basic checks on new fields only

| File | Expected decode | Expected validate | Notes |
| --- | --- | --- | --- |
| share_proof_valid.bin | pass | pass (structural) | Cryptographic verification should fail because proofs are dummy bytes. |
| share_proof_empty_share_proofs.bin | pass | fail | share_proofs is empty. |
| share_proof_empty_kzg_proof.bin | pass | fail | KZGMultiProof.proof is empty. |
| share_proof_mismatched_column_counts.bin | pass | fail | column_proofs length != column_indices length. |
| share_proof_root_mismatch.bin | pass | fail | root_commitment mismatch when compared to expected root. |
| dah_valid_new_fields.bin | pass | pass (shape) | If your ValidateBasic enforces min column commitments, this payload fails because it has 1 column_commitment. |

If a consumer performs full cryptographic verification, only use these vectors to test rejection paths, not acceptance.
