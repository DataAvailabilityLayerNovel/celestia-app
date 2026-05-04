# Proto KZG interop playbook

Purpose: confirm binary protobuf interop for ShareProof and DataAvailabilityHeader using golden vectors.

Inputs:
- proto files: proto/celestia/core/v1/proof/proof.proto, proto/celestia/core/v1/da/data_availability_header.proto
- vectors: docs/architecture/testdata/proto-kzg/*.bin
- expected results: docs/architecture/testdata/proto-kzg/expected_results.md

## Steps

1) Pin the proto revision

Use the commit hash from docs/architecture/proto-kzg-interop-pack.md, then generate code with your tooling.

2) Load and decode vectors

For each .bin file:
- Read file bytes
- Unmarshal into the matching message type
- Record decode success or failure

3) Run validation rules

ShareProof:
- share_proofs is non-empty
- each KZGMultiProof.proof is non-empty
- commitment_proof is present
- len(column_proofs) == len(column_indices)
- if root_commitment is set, compare it to the expected root you supply

DataAvailabilityHeader:
- prefer new fields (piece_commitments, column_commitments, namespace_index)
- if you enforce ValidateBasic, apply it after mapping fields

4) Compare with expected results

Match outcomes against docs/architecture/testdata/proto-kzg/expected_results.md.

## Minimal Go example (consumer side)

```go
package main

import (
	"os"

	corev1da "github.com/celestiaorg/celestia-app/v8/proto/celestia/core/v1/da"
	corev1proof "github.com/celestiaorg/celestia-app/v8/pkg/proof"
	"github.com/gogo/protobuf/proto"
)

func loadShareProof(path string) (*corev1proof.ShareProof, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sp := new(corev1proof.ShareProof)
	return sp, proto.Unmarshal(b, sp)
}

func loadDAH(path string) (*corev1da.DataAvailabilityHeader, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dah := new(corev1da.DataAvailabilityHeader)
	return dah, proto.Unmarshal(b, dah)
}
```

Notes:
- The vectors use placeholder proof bytes. They are for structural checks, not crypto verification.
- If you need a descriptor set, see docs/architecture/proto-kzg-interop-pack.md.
