package proof

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/cda"
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
	"github.com/celestiaorg/celestia-app/v8/pkg/da"
	daproto "github.com/celestiaorg/celestia-app/v8/proto/celestia/core/v1/da"
	share "github.com/celestiaorg/go-square/v4/share"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/stretchr/testify/require"
)

const interopSeed = 2810

func TestInteropFlowInputToDAHMarshalUnmarshal(t *testing.T) {
	inputShares := makeInteropInputShares(t, 256)

	eds, err := da.ExtendShares(inputShares)
	require.NoError(t, err)

	// input -> calculate DAH
	dah, err := da.NewDataAvailabilityHeader(eds)
	require.NoError(t, err)
	require.NotEmpty(t, dah.ColumnComm)

	// DAH -> proto -> marshal
	pdah, err := dah.ToProto()
	require.NoError(t, err)
	wire, err := pdah.Marshal()
	require.NoError(t, err)
	require.NotEmpty(t, wire)

	// unmarshal -> proto -> DAH
	var received daproto.DataAvailabilityHeader
	require.NoError(t, received.Unmarshal(wire))
	restored, err := da.DataAvailabilityHeaderFromProto(&received)
	require.NoError(t, err)

	// hash is memoized lazily on restored object
	restored.Hash()
	require.Equal(t, dah.Hash(), restored.Hash())
	require.Equal(t, dah.ColumnComm, restored.ColumnComm)
}

func TestInteropFlowInputToProofMarshalUnmarshal(t *testing.T) {
	inputShares := makeInteropInputShares(t, 256)

	eds, err := da.ExtendShares(inputShares)
	require.NoError(t, err)

	dah, err := da.NewDataAvailabilityHeader(eds)
	require.NoError(t, err)

	codec := rlnc.NewRLNCCodec(4)
	srs, err := kzg.NewSRS(uint64(eds.Width()*4), big.NewInt(-1))
	require.NoError(t, err)
	provider := cda.NewGnarkKZG(*srs)

	_, err = cda.ComputeAndSetKateCommitments(codec, eds, provider, interopSeed)
	require.NoError(t, err)

	namespace := share.MustNewV0Namespace(bytes.Repeat([]byte{1}, share.NamespaceVersionZeroIDSize))

	// input -> calculate range proof
	rangeProof, err := NewKZGRangeProofFromEDS(eds, &dah, namespace, codec, provider, interopSeed)
	require.NoError(t, err)
	require.NoError(t, VerifyKZGRangeProof(rangeProof, &dah, codec, provider))

	shareProof := buildInteropShareProof(rangeProof, dah.Hash())

	// proof -> marshal
	wire, err := shareProof.Marshal()
	require.NoError(t, err)
	require.NotEmpty(t, wire)

	// unmarshal -> validate semantic contract
	var received ShareProof
	require.NoError(t, received.Unmarshal(wire))
	require.NoError(t, received.Validate(dah.Hash()))
	require.True(t, received.VerifyProofWithKZGRange(rangeProof, &dah, codec, provider))
	require.Equal(t, shareProof.NamespaceId, received.NamespaceId)
	require.Equal(t, shareProof.NamespaceVersion, received.NamespaceVersion)
	require.NotNil(t, received.CommitmentProof)

	// Tampering ShareProof payload should fail contextual verification even if
	// the original range proof remains valid.
	received.CommitmentProof.ColumnProofs[0].Proof[0] ^= 0x01
	require.False(t, received.VerifyProofWithKZGRange(rangeProof, &dah, codec, provider))
}

func buildInteropShareProof(rangeProof *KZGRangeProof, root []byte) ShareProof {
	data := make([][]byte, 0, len(rangeProof.CellProofs))
	shareProofs := make([]*KZGMultiProof, 0, len(rangeProof.CellProofs))
	for _, cp := range rangeProof.CellProofs {
		data = append(data, append([]byte(nil), cp.ShareData...))
		if len(cp.PieceOpenProofs) > 0 {
			shareProofs = append(shareProofs, &KZGMultiProof{Proof: append([]byte(nil), cp.PieceOpenProofs[0]...)})
		}
	}

	columnProofs := make([]*KZGMultiProof, 0, len(rangeProof.ColumnProofs))
	columnIndices := make([]uint32, 0, len(rangeProof.ColumnProofs))
	for _, cp := range rangeProof.ColumnProofs {
		columnProofs = append(columnProofs, &KZGMultiProof{Proof: append([]byte(nil), cp.Commitment...)})
		columnIndices = append(columnIndices, cp.Column)
	}

	return ShareProof{
		Data:             data,
		ShareProofs:      shareProofs,
		NamespaceId:      append([]byte(nil), rangeProof.NamespaceID...),
		NamespaceVersion: rangeProof.NamespaceVersion,
		CommitmentProof: &CommitmentProof{
			ColumnProofs:   columnProofs,
			ColumnIndices:  columnIndices,
			RootCommitment: append([]byte(nil), root...),
		},
	}
}

func makeInteropInputShares(t *testing.T, width int) [][]byte {
	t.Helper()

	namespace := share.MustNewV0Namespace(bytes.Repeat([]byte{1}, share.NamespaceVersionZeroIDSize))
	blobData := bytes.Repeat([]byte{1}, share.AvailableBytesFromSparseShares(width))
	blob, err := share.NewV0Blob(namespace, blobData)
	require.NoError(t, err)

	shares, err := blob.ToShares()
	require.NoError(t, err)
	require.Equal(t, width, len(shares))

	return share.ToBytes(shares)
}
