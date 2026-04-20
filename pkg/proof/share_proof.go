package proof

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/cda"
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
	"github.com/celestiaorg/celestia-app/v8/pkg/da"
)

// Validate runs basic validations on the proof then verifies if it is consistent.
// It returns nil if the proof is valid. Otherwise, it returns a sensible error.
// The `root` is the block data root that the shares to be proven belong to.
// Note: these proofs are tested on the app side.
func (sp ShareProof) Validate(root []byte) error {
	if sp.Data == nil {
		return errors.New("empty share proof")
	}
	if len(sp.ShareProofs) == 0 {
		return errors.New("share_proofs cannot be empty")
	}
	for _, proof := range sp.ShareProofs {
		if len(proof.Proof) == 0 {
			return errors.New("kzg proof bytes cannot be empty")
		}
	}
	if sp.CommitmentProof == nil {
		return errors.New("commitment_proof cannot be nil")
	}
	if len(sp.CommitmentProof.ColumnProofs) == 0 {
		return errors.New("commitment_proof.column_proofs cannot be empty")
	}
	if len(sp.CommitmentProof.ColumnProofs) != len(sp.CommitmentProof.ColumnIndices) {
		return fmt.Errorf("column proofs %d must match column indices %d", len(sp.CommitmentProof.ColumnProofs), len(sp.CommitmentProof.ColumnIndices))
	}
	if len(root) > 0 && len(sp.CommitmentProof.RootCommitment) > 0 && !bytes.Equal(root, sp.CommitmentProof.RootCommitment) {
		return errors.New("root mismatch with commitment_proof.root_commitment")
	}

	if ok := sp.VerifyProof(); !ok {
		return errors.New("share proof failed to verify")
	}

	return nil
}

func (sp ShareProof) VerifyProof() bool {
	return sp.verifyBasicShape()
}

// VerifyProofWithKZGRange verifies ShareProof against a fully verifiable
// KZGRangeProof context (DAH, codec, provider).
//
// ShareProof alone does not carry enough context to run full cryptographic
// verification, so this method reuses VerifyKZGRangeProof and then checks that
// the ShareProof payload matches that verified range proof.
func (sp ShareProof) VerifyProofWithKZGRange(
	rangeProof *KZGRangeProof,
	dah *da.DataAvailabilityHeader,
	codec *rlnc.RLNCCodec,
	provider cda.KZGProvider,
) bool {
	if !sp.verifyBasicShape() {
		return false
	}
	if rangeProof == nil || dah == nil {
		return false
	}
	if err := VerifyKZGRangeProof(rangeProof, dah, codec, provider); err != nil {
		return false
	}

	if !bytes.Equal(sp.NamespaceId, rangeProof.NamespaceID) {
		return false
	}
	if sp.NamespaceVersion != rangeProof.NamespaceVersion {
		return false
	}

	if len(sp.Data) != len(rangeProof.CellProofs) {
		return false
	}
	for i, cell := range rangeProof.CellProofs {
		if !bytes.Equal(sp.Data[i], cell.ShareData) {
			return false
		}
	}

	if len(sp.ShareProofs) != len(rangeProof.CellProofs) {
		return false
	}
	for i, cell := range rangeProof.CellProofs {
		if len(cell.PieceOpenProofs) == 0 {
			return false
		}
		if !bytes.Equal(sp.ShareProofs[i].Proof, cell.PieceOpenProofs[0]) {
			return false
		}
	}

	if sp.CommitmentProof == nil {
		return false
	}
	if len(sp.CommitmentProof.ColumnIndices) != len(rangeProof.ColumnProofs) {
		return false
	}
	if len(sp.CommitmentProof.ColumnProofs) != len(rangeProof.ColumnProofs) {
		return false
	}
	for i, colProof := range rangeProof.ColumnProofs {
		if sp.CommitmentProof.ColumnIndices[i] != colProof.Column {
			return false
		}
		if !bytes.Equal(sp.CommitmentProof.ColumnProofs[i].Proof, colProof.Commitment) {
			return false
		}
	}

	if len(sp.CommitmentProof.RootCommitment) > 0 && !bytes.Equal(sp.CommitmentProof.RootCommitment, dah.Hash()) {
		return false
	}

	return true
}

func (sp ShareProof) verifyBasicShape() bool {
	if len(sp.ShareProofs) == 0 || sp.CommitmentProof == nil {
		return false
	}
	for _, proof := range sp.ShareProofs {
		if len(proof.Proof) == 0 {
			return false
		}
	}
	for _, proof := range sp.CommitmentProof.ColumnProofs {
		if len(proof.Proof) == 0 {
			return false
		}
	}
	return true
}
