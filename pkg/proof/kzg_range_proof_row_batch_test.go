package proof_test

import (
	"math/big"
	"testing"

	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/cda"
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
	"github.com/celestiaorg/celestia-app/v8/pkg/da"
	"github.com/celestiaorg/celestia-app/v8/pkg/proof"
	"github.com/celestiaorg/go-square/v4/share"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/stretchr/testify/require"
)

func newRangeProofForCustomRange(
	t *testing.T,
	start int,
	end int,
) (*proof.KZGRangeProof, *da.DataAvailabilityHeader, *rlnc.RLNCCodec, cda.KZGProvider) {
	t.Helper()

	dataSquare, err := makeOrderedBlobSquare(256)
	require.NoError(t, err)

	eds, err := da.ExtendShares(dataSquare)
	require.NoError(t, err)

	codec := rlnc.NewRLNCCodec(4)
	srs, err := kzg.NewSRS(uint64(eds.Width()*4), big.NewInt(-1))
	require.NoError(t, err)
	provider := cda.NewGnarkKZG(*srs)

	_, err = cda.ComputeAndSetKateCommitments(codec, eds, provider, d)
	require.NoError(t, err)

	dah, err := da.NewDataAvailabilityHeader(eds)
	require.NoError(t, err)

	ns := orderedBlobNamespace()
	dah.NamespaceIndex[string(ns.Bytes())] = share.Range{Start: start, End: end}

	rangeProof, err := proof.NewKZGRangeProofFromEDS(eds, &dah, ns, codec, provider, d)
	require.NoError(t, err)

	return rangeProof, &dah, codec, provider
}

func TestKZGRangeProofRowBatch_Golden(t *testing.T) {
	t.Run("single_row_range", func(t *testing.T) {
		rangeProof, dah, codec, provider := newRangeProofForCustomRange(t, 0, 8)

		require.NotEmpty(t, rangeProof.RowProofs)
		require.Len(t, rangeProof.RowProofs, 1)
		require.NotNil(t, rangeProof.RowBatch)

		err := proof.VerifyKZGRangeProof(rangeProof, dah, codec, provider)
		require.NoError(t, err)
	})

	t.Run("multi_row_range", func(t *testing.T) {
		rangeProof, dah, codec, provider := newRangeProofForCustomRange(t, 8, 40)

		require.NotEmpty(t, rangeProof.RowProofs)
		require.Greater(t, len(rangeProof.RowProofs), 1)
		require.NotNil(t, rangeProof.RowBatch)

		err := proof.VerifyKZGRangeProof(rangeProof, dah, codec, provider)
		require.NoError(t, err)
	})
}

func TestKZGRangeProofRowBatch_NegativeCases(t *testing.T) {
	t.Run("tampered_row_commitment", func(t *testing.T) {
		rangeProof, dah, codec, provider := newRangeProofForCustomRange(t, 8, 40)

		require.NotEmpty(t, rangeProof.RowProofs)
		require.NotEmpty(t, rangeProof.RowProofs[0].CombinedCommitment)
		rangeProof.RowProofs[0].CombinedCommitment[0] ^= 0x01

		err := proof.VerifyKZGRangeProof(rangeProof, dah, codec, provider)
		require.Error(t, err)
	})

	t.Run("tampered_row_proof", func(t *testing.T) {
		rangeProof, dah, codec, provider := newRangeProofForCustomRange(t, 8, 40)

		require.NotEmpty(t, rangeProof.RowProofs)
		require.NotEmpty(t, rangeProof.RowProofs[0].CombinedProof)
		rangeProof.RowProofs[0].CombinedProof[0] ^= 0x01

		err := proof.VerifyKZGRangeProof(rangeProof, dah, codec, provider)
		require.Error(t, err)
	})

	t.Run("tampered_row_batch", func(t *testing.T) {
		rangeProof, dah, codec, provider := newRangeProofForCustomRange(t, 8, 40)

		require.NotNil(t, rangeProof.RowBatch)
		require.NotEmpty(t, rangeProof.RowBatch.Transcript)
		rangeProof.RowBatch.Transcript[0] ^= 0x01

		err := proof.VerifyKZGRangeProof(rangeProof, dah, codec, provider)
		require.Error(t, err)
	})
}

func TestKZGRangeProofRowBatch_Deterministic(t *testing.T) {
	proofA, _, _, _ := newRangeProofForCustomRange(t, 8, 40)
	proofB, _, _, _ := newRangeProofForCustomRange(t, 8, 40)

	require.NotNil(t, proofA.RowBatch)
	require.NotNil(t, proofB.RowBatch)

	require.Equal(t, proofA.RowBatch.Transcript, proofB.RowBatch.Transcript)
	require.Equal(t, proofA.RowBatch.Coeffs, proofB.RowBatch.Coeffs)
	require.Equal(t, proofA.RowBatch.CombinedProof, proofB.RowBatch.CombinedProof)
	require.Equal(t, proofA.RowBatch.CombinedCommitment, proofB.RowBatch.CombinedCommitment)

	require.Len(t, proofA.RowProofs, len(proofB.RowProofs))
	for i := range proofA.RowProofs {
		require.Equal(t, proofA.RowProofs[i].Row, proofB.RowProofs[i].Row)
		require.Equal(t, proofA.RowProofs[i].Columns, proofB.RowProofs[i].Columns)
		require.Equal(t, proofA.RowProofs[i].Coeffs, proofB.RowProofs[i].Coeffs)
		require.Equal(t, proofA.RowProofs[i].CombinedProof, proofB.RowProofs[i].CombinedProof)
		require.Equal(t, proofA.RowProofs[i].CombinedCommitment, proofB.RowProofs[i].CombinedCommitment)
	}
}
