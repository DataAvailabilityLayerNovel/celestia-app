package proof

import (
	"bytes"
	"fmt"
	"sort"

	rsmt2d "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d"
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/cda"
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
	"github.com/celestiaorg/celestia-app/v8/pkg/da"
	square "github.com/celestiaorg/go-square/v4"
	"github.com/celestiaorg/go-square/v4/share"
	"github.com/cometbft/cometbft/crypto/merkle"
	bls12381kzg "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
)

// KZGRangeProof is a wire-format proof for a namespace share range.
// Phase 1 proves affected column commitments are included in the header root.
// Phase 2 proves each cell opening against its column commitment.
type KZGRangeProof struct {
	NamespaceID      []byte
	NamespaceVersion uint32

	StartCell uint32
	EndCell   uint32 // end-exclusive

	DataRoot  []byte
	Width     uint32
	MaxChunks uint32

	ColumnProofs []KZGColumnProof
	CellProofs   []KZGCellProof
}

// KZGColumnProof links one column commitment to the header root.
type KZGColumnProof struct {
	Column     uint32
	Commitment []byte
	Proof      *Proof
}

// KZGCellProof carries one cell and its k opening proofs.
type KZGCellProof struct {
	Row             uint32
	Column          uint32
	ShareData       []byte
	PieceOpenProofs [][]byte
}

// NewKZGRangeProofFromEDS builds a range proof aligned with DAH commitments.
func NewKZGRangeProofFromEDS(
	eds *rsmt2d.ExtendedDataSquare,
	dah *da.DataAvailabilityHeader,
	namespace share.Namespace,
	codec *rlnc.RLNCCodec,
	provider cda.KZGProvider,
) (*KZGRangeProof, error) {
	if eds == nil || dah == nil || codec == nil || provider == nil {
		return nil, fmt.Errorf("nil input provided")
	}

	nsRange, ok := dah.NamespaceRange(namespace.Bytes())
	if !ok {
		return nil, fmt.Errorf("namespace %x not found in DAH namespace index", namespace.Bytes())
	}
	if nsRange.Start < 0 || nsRange.End <= nsRange.Start {
		return nil, fmt.Errorf("invalid namespace range: [%d, %d)", nsRange.Start, nsRange.End)
	}

	squareSize, err := square.Size(len(eds.FlattenedODS()))
	if err != nil {
		return nil, err
	}
	width := int(eds.Width())
	k := codec.MaxChunks()
	if k <= 0 {
		return nil, fmt.Errorf("invalid codec max chunks: %d", k)
	}

	// Build Merkle proofs directly from header commitments to match header hash.
	_, allProofs := merkle.ProofsFromByteSlices(dah.ColumnComm)

	affectedCols := make(map[int]struct{})
	cellIndices := make([]int, 0, nsRange.End-nsRange.Start)
	for idx := nsRange.Start; idx < nsRange.End; idx++ {
		row := idx / squareSize
		col := idx % squareSize
		if row < 0 || row >= squareSize || col < 0 || col >= squareSize {
			return nil, fmt.Errorf("cell index %d maps out of ODS bounds", idx)
		}
		affectedCols[col] = struct{}{}
		cellIndices = append(cellIndices, idx)
	}

	cols := make([]int, 0, len(affectedCols))
	for col := range affectedCols {
		cols = append(cols, col)
	}
	sort.Ints(cols)

	columnProofs := make([]KZGColumnProof, 0, len(cols))
	for _, col := range cols {
		if col >= len(dah.ColumnComm) {
			return nil, fmt.Errorf("column %d out of header commitment bounds", col)
		}
		p := allProofs[col]
		columnProofs = append(columnProofs, KZGColumnProof{
			Column:     uint32(col),
			Commitment: append([]byte(nil), dah.ColumnComm[col]...),
			Proof: &Proof{
				Total:    p.Total,
				Index:    p.Index,
				LeafHash: append([]byte(nil), p.LeafHash...),
				Aunts:    clone2D(p.Aunts),
			},
		})
	}

	allOpenProofs, err := cda.ComputeOpenProofCells(codec, eds, provider)
	if err != nil {
		return nil, err
	}

	cellProofs := make([]KZGCellProof, 0, len(cellIndices))
	for _, idx := range cellIndices {
		row := idx / squareSize
		col := idx % squareSize
		rowData := eds.Row(uint(row))
		if col >= len(rowData) {
			return nil, fmt.Errorf("column %d out of row width", col)
		}

		proofStart := ((row * width) + col) * k
		if proofStart+k > len(allOpenProofs) {
			return nil, fmt.Errorf("open proof slice out of bounds for row=%d col=%d", row, col)
		}

		pieceProofs := make([][]byte, k)
		for i := 0; i < k; i++ {
			pieceProofs[i] = append([]byte(nil), allOpenProofs[proofStart+i]...)
		}

		cellProofs = append(cellProofs, KZGCellProof{
			Row:             uint32(row),
			Column:          uint32(col),
			ShareData:       append([]byte(nil), rowData[col]...),
			PieceOpenProofs: pieceProofs,
		})
	}

	return &KZGRangeProof{
		NamespaceID:      append([]byte(nil), namespace.ID()...),
		NamespaceVersion: uint32(namespace.Version()),
		StartCell:        uint32(nsRange.Start),
		EndCell:          uint32(nsRange.End),
		DataRoot:         append([]byte(nil), dah.Hash()...),
		Width:            uint32(width),
		MaxChunks:        uint32(k),
		ColumnProofs:     columnProofs,
		CellProofs:       cellProofs,
	}, nil
}

// VerifyKZGRangeProof verifies a range proof in two phases:
// 1) commitment inclusion against header root
// 2) per-cell opening verification against column commitments
func VerifyKZGRangeProof(
	proof *KZGRangeProof,
	dah *da.DataAvailabilityHeader,
	codec *rlnc.RLNCCodec,
	provider cda.KZGProvider,
) error {
	if proof == nil || dah == nil || codec == nil || provider == nil {
		return fmt.Errorf("nil input provided")
	}
	if proof.StartCell >= proof.EndCell {
		return fmt.Errorf("invalid range [%d, %d)", proof.StartCell, proof.EndCell)
	}
	if !bytes.Equal(proof.DataRoot, dah.Hash()) {
		return fmt.Errorf("proof data root does not match header hash")
	}
	if int(proof.Width) == 0 || int(proof.MaxChunks) != codec.MaxChunks() {
		return fmt.Errorf("invalid proof width/max chunks")
	}

	verifiedCols := make(map[uint32][]byte, len(proof.ColumnProofs))
	for _, cp := range proof.ColumnProofs {
		col := int(cp.Column)
		if col < 0 || col >= len(dah.ColumnComm) {
			return fmt.Errorf("column %d out of header bounds", cp.Column)
		}
		if !bytes.Equal(cp.Commitment, dah.ColumnComm[col]) {
			return fmt.Errorf("column %d commitment mismatch with header", cp.Column)
		}
		if cp.Proof == nil {
			return fmt.Errorf("column %d has nil merkle proof", cp.Column)
		}
		if err := cp.Proof.Verify(proof.DataRoot, cp.Commitment); err != nil {
			return fmt.Errorf("column %d merkle proof invalid: %w", cp.Column, err)
		}
		verifiedCols[cp.Column] = cp.Commitment
	}

	k := codec.MaxChunks()
	for _, cell := range proof.CellProofs {
		commitment, ok := verifiedCols[cell.Column]
		if !ok {
			return fmt.Errorf("cell references unverified column %d", cell.Column)
		}
		if len(cell.PieceOpenProofs) != k {
			return fmt.Errorf("cell (%d,%d) has %d piece proofs, expected %d", cell.Row, cell.Column, len(cell.PieceOpenProofs), k)
		}

		pieceProofs := make([][]byte, k)
		for i := 0; i < k; i++ {
			pieceProofs[i] = cda.PieceCommitment(cell.PieceOpenProofs[i])
		}

		coeffs := codec.GenerateCoeffsByColHeight(int(cell.Column), int(proof.Width))
		combinedProof, err := provider.CombineProofs(pieceProofs, coeffs)
		if err != nil {
			return fmt.Errorf("combine proofs for cell (%d,%d): %w", cell.Row, cell.Column, err)
		}

		opening := new(bls12381kzg.OpeningProof)
		if _, err := opening.ReadFrom(bytes.NewReader(combinedProof)); err != nil {
			return fmt.Errorf("decode combined proof for cell (%d,%d): %w", cell.Row, cell.Column, err)
		}
		claimed := opening.ClaimedValue.Bytes()

		if ok := provider.Verify(cda.PieceCommitment(commitment), int(cell.Row), claimed[:], combinedProof); !ok {
			return fmt.Errorf("pairing verification failed for cell (%d,%d)", cell.Row, cell.Column)
		}
	}

	return nil
}

func clone2D(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = append([]byte(nil), in[i]...)
	}
	return out
}
