package proof_test

import (
	"bytes"
	"math/big"
	"testing"

	rsmt2d "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d"
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/cda"
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
	"github.com/celestiaorg/celestia-app/v8/pkg/da"
	"github.com/celestiaorg/celestia-app/v8/pkg/proof"
	"github.com/celestiaorg/go-square/v4/share"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const d = 2810

func TestKateCommitmentsAndColumnProofs(t *testing.T) {
	dataSquare, err := makeOrderedBlobSquare(256)
	require.NoError(t, err)

	texts, err := da.ExtendShares(dataSquare)
	require.NoError(t, err)
	setKateCommitments(t, texts)

	dah, err := da.NewDataAvailabilityHeader(texts)
	require.NoError(t, err)

	kateRoot, err := texts.KateRoot()
	require.NoError(t, err)
	assert.NotEmpty(t, kateRoot)

	require.Len(t, dah.ColumnComm, int(texts.Width()))

	proof, err := texts.BuildKateCommitmentProof(1)
	require.NoError(t, err)
	assert.NotNil(t, proof)
	assert.NotEmpty(t, dah.Hash())
}

func TestKateRootRequiresCommitments(t *testing.T) {
	dataSquare, err := makeOrderedBlobSquare(256)
	require.NoError(t, err)

	texts, err := da.ExtendShares(dataSquare)
	require.NoError(t, err)

	// NewDataAvailabilityHeader now auto-computes commitments, so no error expected
	dah, err := da.NewDataAvailabilityHeader(texts)
	require.NoError(t, err)
	require.NotNil(t, dah)
}

func TestColumnCommitmentDeterministicCombine(t *testing.T) {
	dataSquare, err := makeOrderedBlobSquare(256)
	require.NoError(t, err)

	eds, err := da.ExtendShares(dataSquare)
	require.NoError(t, err)

	codec := rlnc.NewRLNCCodec(4)
	srs, err := kzg.NewSRS(128, big.NewInt(-1))
	require.NoError(t, err)
	provider := cda.NewGnarkKZG(*srs)

	pubData, err := cda.ComputeAndSetKateCommitments(codec, eds, provider, d)
	require.NoError(t, err)

	k := codec.MaxChunks()
	n := int(eds.Width())
	require.Len(t, pubData.PieceComm, n*k)
	require.Len(t, pubData.ColumnComm, n)

	for col := 0; col < n; col++ {
		coeffs := codec.GenerateCoeffsByColSeed(col, d)
		start := col * k
		combined, err := provider.Combine(pubData.PieceComm[start:start+k], coeffs)
		require.NoError(t, err)
		assert.Equal(t, []byte(pubData.ColumnComm[col]), []byte(combined))
	}
}

func TestPerCellPairingVerificationFlow(t *testing.T) {
	dataSquare, err := makeOrderedBlobSquare(256)
	require.NoError(t, err)

	eds, err := da.ExtendShares(dataSquare)
	require.NoError(t, err)

	codec := rlnc.NewRLNCCodec(4)
	srs, err := kzg.NewSRS(128, big.NewInt(-1))
	require.NoError(t, err)
	provider := cda.NewGnarkKZG(*srs)

	pubData, err := cda.ComputeAndSetKateCommitments(codec, eds, provider, d)
	require.NoError(t, err)

	openProofs, err := cda.ComputeOpenProofCells(codec, eds, provider)
	require.NoError(t, err)

	n := int(eds.Width())
	k := codec.MaxChunks()
	row := n / 2
	col := n / 3

	cellProofs := proofsForCell(openProofs, row, col, n, k)
	require.Len(t, cellProofs, k)

	combinedProof, err := provider.CombineProofs(cellProofs, codec.GenerateCoeffsByColSeed(col, d))
	require.NoError(t, err)

	// Use the claimed value encoded in the combined opening proof as verify input.
	openingProof := new(kzg.OpeningProof)
	_, err = openingProof.ReadFrom(bytes.NewReader(combinedProof))
	require.NoError(t, err)
	combinedValue := openingProof.ClaimedValue.Bytes()

	ok := provider.Verify(pubData.ColumnComm[col], row, combinedValue[:], combinedProof)
	assert.True(t, ok)
}

func TestBuildAndVerifyKZGRangeProof(t *testing.T) {
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
	rangeProof, err := proof.NewKZGRangeProofFromEDS(eds, &dah, ns, codec, provider, d)
	require.NoError(t, err)
	require.NotEmpty(t, rangeProof.RowProofs)
	require.NotNil(t, rangeProof.RowBatch)

	err = proof.VerifyKZGRangeProof(rangeProof, &dah, codec, provider)
	require.NoError(t, err)
}

func TestVerifyKZGRangeProofRejectsTamperedRowProof(t *testing.T) {
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
	rangeProof, err := proof.NewKZGRangeProofFromEDS(eds, &dah, ns, codec, provider, d)
	require.NoError(t, err)
	require.NotEmpty(t, rangeProof.RowProofs)
	require.NotEmpty(t, rangeProof.RowProofs[0].CombinedProof)

	rangeProof.RowProofs[0].CombinedProof[0] ^= 0x01
	err = proof.VerifyKZGRangeProof(rangeProof, &dah, codec, provider)
	require.Error(t, err)
}

func TestVerifyKZGRangeProofRejectsTamperedRowBatch(t *testing.T) {
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
	rangeProof, err := proof.NewKZGRangeProofFromEDS(eds, &dah, ns, codec, provider, d)
	require.NoError(t, err)
	require.NotNil(t, rangeProof.RowBatch)
	require.NotEmpty(t, rangeProof.RowBatch.CombinedCommitment)

	rangeProof.RowBatch.CombinedCommitment[0] ^= 0x01
	err = proof.VerifyKZGRangeProof(rangeProof, &dah, codec, provider)
	require.Error(t, err)
}

func TestVerifyKZGRangeProofRejectsTamperedColumnCommitment(t *testing.T) {
	dataSquare, err := makeOrderedBlobSquare(256)
	require.NoError(t, err)

	eds, err := da.ExtendShares(dataSquare)
	require.NoError(t, err)

	codec := rlnc.NewRLNCCodec(4)
	srs, err := kzg.NewSRS(128, big.NewInt(-1))
	require.NoError(t, err)
	provider := cda.NewGnarkKZG(*srs)

	_, err = cda.ComputeAndSetKateCommitments(codec, eds, provider, d)
	require.NoError(t, err)

	dah, err := da.NewDataAvailabilityHeader(eds)
	require.NoError(t, err)

	ns := orderedBlobNamespace()
	rangeProof, err := proof.NewKZGRangeProofFromEDS(eds, &dah, ns, codec, provider, d)
	require.NoError(t, err)
	require.NotEmpty(t, rangeProof.ColumnProofs)

	rangeProof.ColumnProofs[0].Commitment[0] ^= 0x01
	err = proof.VerifyKZGRangeProof(rangeProof, &dah, codec, provider)
	require.Error(t, err)
}

func makeOrderedBlobSquare(width int) ([][]byte, error) {
	namespace := orderedBlobNamespace()
	blobData := bytes.Repeat([]byte{1}, share.AvailableBytesFromSparseShares(width))
	blob, err := share.NewV0Blob(namespace, blobData)
	if err != nil {
		return nil, err
	}
	shares, err := blob.ToShares()
	if err != nil {
		return nil, err
	}
	if len(shares) != width {
		return nil, assert.AnError
	}
	return share.ToBytes(shares), nil
}

func orderedBlobNamespace() share.Namespace {
	return share.MustNewV0Namespace(bytes.Repeat([]byte{1}, share.NamespaceVersionZeroIDSize))
}

func setKateCommitments(t *testing.T, eds *rsmt2d.ExtendedDataSquare) {
	t.Helper()

	codec := rlnc.NewRLNCCodec(4)
	srs, err := kzg.NewSRS(uint64(eds.Width()*4), big.NewInt(-1))
	require.NoError(t, err)
	provider := cda.NewGnarkKZG(*srs)

	_, err = cda.ComputeAndSetKateCommitments(codec, eds, provider, d)
	require.NoError(t, err)
}

func proofsForCell(allProofs [][]byte, row, col, width, k int) [][]byte {
	idx := ((row * width) + col) * k
	proofs := make([][]byte, k)
	for i := 0; i < k; i++ {
		proofs[i] = allProofs[idx+i]
	}
	return proofs
}
