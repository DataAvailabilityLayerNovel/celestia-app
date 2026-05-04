package main

import (
	"os"
	"path/filepath"

	corev1proof "github.com/celestiaorg/celestia-app/v8/pkg/proof"
	corev1da "github.com/celestiaorg/celestia-app/v8/proto/celestia/core/v1/da"
	"github.com/gogo/protobuf/proto"
)

func main() {
	outDir := filepath.Join("docs", "architecture", "testdata", "proto-kzg")
	os.MkdirAll(outDir, 0755)

	// 1. ShareProof valid
	spValid := &corev1proof.ShareProof{
		Data:        [][]byte{[]byte("data1")},
		ShareProofs: []*corev1proof.KZGMultiProof{{Proof: []byte("proof1")}},
		NamespaceId: []byte("ns1"),
		CommitmentProof: &corev1proof.CommitmentProof{
			ColumnProofs:  []*corev1proof.KZGMultiProof{{Proof: []byte("colproof1")}},
			ColumnIndices: []uint32{0},
		},
		NamespaceVersion: 0,
	}
	save(filepath.Join(outDir, "share_proof_valid.bin"), spValid)

	// 2. ShareProof empty proofs
	spEmptyProofs := &corev1proof.ShareProof{
		Data:        [][]byte{[]byte("data1")},
		ShareProofs: []*corev1proof.KZGMultiProof{}, // empty
		NamespaceId: []byte("ns1"),
		CommitmentProof: &corev1proof.CommitmentProof{
			ColumnProofs:  []*corev1proof.KZGMultiProof{{Proof: []byte("colproof1")}},
			ColumnIndices: []uint32{0},
		},
		NamespaceVersion: 0,
	}
	save(filepath.Join(outDir, "share_proof_empty_share_proofs.bin"), spEmptyProofs)

	spEmptyKZGProof := &corev1proof.ShareProof{
		Data:        [][]byte{[]byte("data1")},
		ShareProofs: []*corev1proof.KZGMultiProof{{Proof: []byte{}}}, // empty inside
		NamespaceId: []byte("ns1"),
		CommitmentProof: &corev1proof.CommitmentProof{
			ColumnProofs:  []*corev1proof.KZGMultiProof{{Proof: []byte("colproof1")}},
			ColumnIndices: []uint32{0},
		},
		NamespaceVersion: 0,
	}
	save(filepath.Join(outDir, "share_proof_empty_kzg_proof.bin"), spEmptyKZGProof)

	// 3. ShareProof mismatched column proofs/indices
	spMismatchCol := &corev1proof.ShareProof{
		Data:        [][]byte{[]byte("data1")},
		ShareProofs: []*corev1proof.KZGMultiProof{{Proof: []byte("proof1")}},
		NamespaceId: []byte("ns1"),
		CommitmentProof: &corev1proof.CommitmentProof{
			ColumnProofs:  []*corev1proof.KZGMultiProof{{Proof: []byte("colproof1")}, {Proof: []byte("colproof2")}},
			ColumnIndices: []uint32{0}, // mismatch
		},
		NamespaceVersion: 0,
	}
	save(filepath.Join(outDir, "share_proof_mismatched_column_counts.bin"), spMismatchCol)

	// 4. ShareProof root mismatch
	spRootMismatch := &corev1proof.ShareProof{
		Data:        [][]byte{[]byte("data1")},
		ShareProofs: []*corev1proof.KZGMultiProof{{Proof: []byte("proof1")}},
		NamespaceId: []byte("ns1"),
		CommitmentProof: &corev1proof.CommitmentProof{
			ColumnProofs:   []*corev1proof.KZGMultiProof{{Proof: []byte("colproof1")}},
			ColumnIndices:  []uint32{0},
			RootCommitment: []byte("wrong_root"), // will fail when checked against correct root
		},
		NamespaceVersion: 0,
	}
	save(filepath.Join(outDir, "share_proof_root_mismatch.bin"), spRootMismatch)

	// 5. DataAvailabilityHeader valid (using new fields)
	dahValid := &corev1da.DataAvailabilityHeader{
		PieceCommitments:  [][]byte{[]byte("piece1")},
		ColumnCommitments: [][]byte{[]byte("col1")}, // note: normally should have at least minExtendedSquareWidth (e.g. 2 for 1x1 base)
		NamespaceIndex: []*corev1da.NamespaceRangeEntry{
			{NamespaceId: []byte("ns1"), Start: 0, End: 1},
		},
	}
	save(filepath.Join(outDir, "dah_valid_new_fields.bin"), dahValid)
}

func save(path string, msg proto.Message) {
	data, err := proto.Marshal(msg)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		panic(err)
	}
}
