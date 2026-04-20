package proof

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"

	rsmt2d "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d"
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/cda"
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
	"github.com/celestiaorg/celestia-app/v8/pkg/appconsts"
	"github.com/celestiaorg/celestia-app/v8/pkg/da"
	"github.com/celestiaorg/celestia-app/v8/pkg/wrapper"
	"github.com/celestiaorg/go-square/v4"
	"github.com/celestiaorg/go-square/v4/share"
	blobtx "github.com/celestiaorg/go-square/v4/tx"
	bls12381kzg "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
)

const defaultKZGProofSeed = 2810

// NewTxInclusionProof returns a new share inclusion proof for the given
// transaction index.
func NewTxInclusionProof(txs [][]byte, txIndex, _ uint64) (ShareProof, error) {
	if txIndex >= uint64(len(txs)) {
		return ShareProof{}, fmt.Errorf("txIndex %d out of bounds", txIndex)
	}

	builder, err := square.NewBuilder(appconsts.SquareSizeUpperBound, appconsts.SubtreeRootThreshold, txs...)
	if err != nil {
		return ShareProof{}, err
	}

	dataSquare, err := builder.Export()
	if err != nil {
		return ShareProof{}, err
	}

	txIndexInt, err := safeConvertUint64ToInt(txIndex)
	if err != nil {
		return ShareProof{}, err
	}
	shareRange, err := builder.FindTxShareRange(txIndexInt)
	if err != nil {
		return ShareProof{}, err
	}

	namespace := getTxNamespace(txs[txIndex])
	return NewShareInclusionProof(dataSquare, namespace, shareRange)
}

// NewShareInclusionProof takes an ODS, extends it, then
// returns an NMT inclusion proof for a set of shares
// belonging to the same namespace to the data root.
// Expects the share range to be pre-validated.
func NewShareInclusionProof(
	dataSquare square.Square,
	namespace share.Namespace,
	shareRange share.Range,
) (ShareProof, error) {
	ods := share.ToBytes(dataSquare)
	eds, err := da.ExtendShares(ods)
	if err != nil {
		return ShareProof{}, err
	}

	return NewShareInclusionProofFromEDS(eds, namespace, shareRange)
}

// NewShareInclusionProofFromEDS takes an extended data square,
// and returns an NMT inclusion proof for a set of shares
// belonging to the same namespace to the data root.
// Expects the share range to be pre-validated.
func NewShareInclusionProofFromEDS(
	eds *rsmt2d.ExtendedDataSquare,
	namespace share.Namespace,
	shareRange share.Range,
) (ShareProof, error) {
	if eds == nil {
		return ShareProof{}, fmt.Errorf("eds cannot be nil")
	}
	if shareRange.End <= shareRange.Start {
		return ShareProof{}, fmt.Errorf("invalid share range [%d,%d)", shareRange.Start, shareRange.End)
	}

	squareSize, err := square.Size(len(eds.FlattenedODS()))
	if err != nil {
		return ShareProof{}, err
	}
	maxShares := squareSize * squareSize
	if shareRange.Start < 0 || shareRange.End > maxShares {
		return ShareProof{}, fmt.Errorf("share range [%d,%d) out of ODS bounds [0,%d)", shareRange.Start, shareRange.End, maxShares)
	}

	dah, err := da.NewDataAvailabilityHeader(eds)
	if err != nil {
		return ShareProof{}, err
	}

	codec, provider, err := buildKZGProofContext(eds)
	if err != nil {
		return ShareProof{}, err
	}

	rangeProof, err := NewKZGRangeProofForRangeFromEDS(eds, &dah, namespace, shareRange, codec, provider, defaultKZGProofSeed)
	if err != nil {
		return ShareProof{}, err
	}

	return shareProofFromKZGRange(rangeProof, dah.Hash())
}

func getTxNamespace(tx []byte) (ns share.Namespace) {
	_, isBlobTx, _ := blobtx.UnmarshalBlobTx(tx)
	if isBlobTx {
		return share.PayForBlobNamespace
	}
	return share.TxNamespace
}

func safeConvertUint64ToInt(val uint64) (int, error) {
	if val > math.MaxInt {
		return 0, fmt.Errorf("value %d is too large to convert to int", val)
	}
	return int(val), nil
}

func buildKZGProofContext(eds *rsmt2d.ExtendedDataSquare) (*rlnc.RLNCCodec, cda.KZGProvider, error) {
	codec := rlnc.NewRLNCCodec(4)
	srsSize := uint64(eds.Width() * 4)
	srs, err := bls12381kzg.NewSRS(srsSize, big.NewInt(-1))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create KZG SRS: %w", err)
	}
	provider := cda.NewGnarkKZG(*srs)
	return codec, provider, nil
}

func shareProofFromKZGRange(rangeProof *KZGRangeProof, root []byte) (ShareProof, error) {
	if rangeProof == nil {
		return ShareProof{}, fmt.Errorf("kzg range proof cannot be nil")
	}

	data := make([][]byte, 0, len(rangeProof.CellProofs))
	shareProofs := make([]*KZGMultiProof, 0, len(rangeProof.CellProofs))
	for _, cell := range rangeProof.CellProofs {
		if len(cell.PieceOpenProofs) == 0 {
			return ShareProof{}, fmt.Errorf("cell (%d,%d) has no piece opening proof", cell.Row, cell.Column)
		}
		data = append(data, append([]byte(nil), cell.ShareData...))
		shareProofs = append(shareProofs, &KZGMultiProof{Proof: append([]byte(nil), cell.PieceOpenProofs[0]...)})
	}

	columnProofs := make([]*KZGMultiProof, 0, len(rangeProof.ColumnProofs))
	columnIndices := make([]uint32, 0, len(rangeProof.ColumnProofs))
	for _, colProof := range rangeProof.ColumnProofs {
		columnProofs = append(columnProofs, &KZGMultiProof{Proof: append([]byte(nil), colProof.Commitment...)})
		columnIndices = append(columnIndices, colProof.Column)
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
	}, nil
}

// CreateShareToRowRootProofs takes a set of shares and their corresponding row roots, and generates
// an NMT inclusion proof of a set of shares, defined by startLeaf and endLeaf, to their corresponding row roots.
func CreateShareToRowRootProofs(squareSize int, rowShares [][]share.Share, rowRoots [][]byte, startLeaf, endLeaf int) ([]*NMTProof, [][]byte, error) {
	shareProofs := make([]*NMTProof, 0, len(rowRoots))
	var rawShares [][]byte
	for i, row := range rowShares {
		// create an nmt to generate a proof.
		// we have to re-create the tree as the eds one is not accessible.
		tree := wrapper.NewErasuredNamespacedMerkleTree(uint64(squareSize), uint(i))
		for _, share := range row {
			err := tree.Push(
				share.ToBytes(),
			)
			if err != nil {
				return nil, nil, err
			}
		}

		// make sure that the generated root is the same as the eds row root.
		root, err := tree.Root()
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(rowRoots[i], root) {
			return nil, nil, errors.New("eds row root is different than tree root")
		}

		startLeafPos := startLeaf
		endLeafPos := endLeaf

		// if this is not the first row, then start with the first leaf
		if i > 0 {
			startLeafPos = 0
		}
		// if this is not the last row, then select for the rest of the row
		if i != (len(rowShares) - 1) {
			endLeafPos = squareSize - 1
		}

		rawShares = append(rawShares, share.ToBytes(row[startLeafPos:endLeafPos+1])...)
		proof, err := tree.ProveRange(startLeafPos, endLeafPos+1)
		if err != nil {
			return nil, nil, err
		}

		shareProofs = append(shareProofs, &NMTProof{
			Start:    int32(proof.Start()),
			End:      int32(proof.End()),
			Nodes:    proof.Nodes(),
			LeafHash: proof.LeafHash(),
		})
	}
	return shareProofs, rawShares, nil
}

func errorsNewLegacyUnsupported() error {
	return fmt.Errorf("legacy NMT share inclusion proof is removed; use KZG range proof APIs")
}
