package proof

import (
	"bytes"
	"crypto/sha256"
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
	Seed      int // seed used for deterministic coefficient generation

	ColumnProofs []KZGColumnProof
	CellProofs   []KZGCellProof
	RowProofs    []KZGRowProof
	RowBatch     *KZGRowBatch
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

// KZGRowProof carries one aggregated proof per row.
// Each row proof aggregates per-cell combined proofs in the same row.
type KZGRowProof struct {
	Row                uint32
	Columns            []uint32
	Coeffs             []byte
	CellCombinedProofs [][]byte
	CombinedProof      []byte
	CombinedCommitment []byte
}

// KZGRowBatch carries level-2 aggregation over row proofs.
// With current cda API we verify batch consistency deterministically,
// then verify each row proof cryptographically.
type KZGRowBatch struct {
	Transcript         []byte
	Coeffs             []byte
	CombinedProof      []byte
	CombinedCommitment []byte
}

// NewKZGRangeProofFromEDS builds a range proof aligned with DAH commitments.
func NewKZGRangeProofFromEDS(
	eds *rsmt2d.ExtendedDataSquare,
	dah *da.DataAvailabilityHeader,
	namespace share.Namespace,
	codec *rlnc.RLNCCodec,
	provider cda.KZGProvider,
	seed int,
) (*KZGRangeProof, error) {
	nsRange, ok := dah.NamespaceRange(namespace.Bytes())
	if !ok {
		return nil, fmt.Errorf("namespace %x not found in DAH namespace index", namespace.Bytes())
	}

	return newKZGRangeProofFromEDSWithBounds(eds, dah, namespace, nsRange.Start, nsRange.End, codec, provider, seed)
}

// NewKZGRangeProofForRangeFromEDS builds a proof for a specific share range
// inside a namespace.
func NewKZGRangeProofForRangeFromEDS(
	eds *rsmt2d.ExtendedDataSquare,
	dah *da.DataAvailabilityHeader,
	namespace share.Namespace,
	shareRange share.Range,
	codec *rlnc.RLNCCodec,
	provider cda.KZGProvider,
	seed int,
) (*KZGRangeProof, error) {
	nsRange, ok := dah.NamespaceRange(namespace.Bytes())
	if !ok {
		return nil, fmt.Errorf("namespace %x not found in DAH namespace index", namespace.Bytes())
	}

	if shareRange.Start < nsRange.Start || shareRange.End > nsRange.End {
		return nil, fmt.Errorf(
			"share range [%d,%d) is outside namespace range [%d,%d)",
			shareRange.Start,
			shareRange.End,
			nsRange.Start,
			nsRange.End,
		)
	}

	return newKZGRangeProofFromEDSWithBounds(eds, dah, namespace, shareRange.Start, shareRange.End, codec, provider, seed)
}

func newKZGRangeProofFromEDSWithBounds(
	eds *rsmt2d.ExtendedDataSquare,
	dah *da.DataAvailabilityHeader,
	namespace share.Namespace,
	rangeStart int,
	rangeEnd int,
	codec *rlnc.RLNCCodec,
	provider cda.KZGProvider,
	seed int,
) (*KZGRangeProof, error) {
	if eds == nil || dah == nil || codec == nil || provider == nil {
		return nil, fmt.Errorf("nil input provided")
	}
	if rangeStart < 0 || rangeEnd <= rangeStart {
		return nil, fmt.Errorf("invalid namespace range: [%d, %d)", rangeStart, rangeEnd)
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
	cellIndices := make([]int, 0, rangeEnd-rangeStart)
	for idx := rangeStart; idx < rangeEnd; idx++ {
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

	rowProofs, err := buildRowProofs(cellProofs, dah, codec, provider, seed)
	if err != nil {
		return nil, err
	}

	rowBatch, err := buildRowBatch(rowProofs, dah.Hash(), namespace.ID(), uint32(namespace.Version()), provider)
	if err != nil {
		return nil, err
	}

	return &KZGRangeProof{
		NamespaceID:      append([]byte(nil), namespace.ID()...),
		NamespaceVersion: uint32(namespace.Version()),
		StartCell:        uint32(rangeStart),
		EndCell:          uint32(rangeEnd),
		DataRoot:         append([]byte(nil), dah.Hash()...),
		Width:            uint32(width),
		MaxChunks:        uint32(k),
		Seed:             seed,
		ColumnProofs:     columnProofs,
		CellProofs:       cellProofs,
		RowProofs:        rowProofs,
		RowBatch:         rowBatch,
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

	if len(proof.RowProofs) > 0 {
		if proof.RowBatch != nil {
			if err := verifyRowBatch(proof.RowBatch, proof.RowProofs, proof.DataRoot, proof.NamespaceID, proof.NamespaceVersion, provider); err != nil {
				return err
			}
		}
		if err := verifyRowProofs(proof.RowProofs, verifiedCols, provider); err != nil {
			return err
		}
		return nil
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

		coeffs := codec.GenerateCoeffsByColSeed(int(cell.Column), proof.Seed)
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

func buildRowProofs(
	cellProofs []KZGCellProof,
	dah *da.DataAvailabilityHeader,
	codec *rlnc.RLNCCodec,
	provider cda.KZGProvider,
	seed int,
) ([]KZGRowProof, error) {
	byRow := make(map[uint32][]KZGCellProof)
	for _, cp := range cellProofs {
		byRow[cp.Row] = append(byRow[cp.Row], cp)
	}

	rows := make([]int, 0, len(byRow))
	for row := range byRow {
		rows = append(rows, int(row))
	}
	sort.Ints(rows)

	rowProofs := make([]KZGRowProof, 0, len(rows))
	k := codec.MaxChunks()
	for _, row := range rows {
		cells := byRow[uint32(row)]
		sort.Slice(cells, func(i, j int) bool {
			return cells[i].Column < cells[j].Column
		})

		coeffs := deriveRowCoeffs(seed, row, len(cells))
		cellCombinedProofs := make([][]byte, 0, len(cells))
		commitments := make([]cda.PieceCommitment, 0, len(cells))
		columns := make([]uint32, 0, len(cells))

		for _, cell := range cells {
			if len(cell.PieceOpenProofs) != k {
				return nil, fmt.Errorf("cell (%d,%d) has %d piece proofs, expected %d", cell.Row, cell.Column, len(cell.PieceOpenProofs), k)
			}

			pieceProofs := make([][]byte, k)
			for i := 0; i < k; i++ {
				pieceProofs[i] = cda.PieceCommitment(cell.PieceOpenProofs[i])
			}
			cellCoeffs := codec.GenerateCoeffsByColSeed(int(cell.Column), seed)
			combinedProof, err := provider.CombineProofs(pieceProofs, cellCoeffs)
			if err != nil {
				return nil, fmt.Errorf("combine proofs for cell (%d,%d): %w", cell.Row, cell.Column, err)
			}

			col := int(cell.Column)
			if col < 0 || col >= len(dah.ColumnComm) {
				return nil, fmt.Errorf("column %d out of header commitment bounds", col)
			}

			columns = append(columns, cell.Column)
			cellCombinedProofs = append(cellCombinedProofs, combinedProof)
			commitments = append(commitments, cda.PieceCommitment(dah.ColumnComm[col]))
		}

		rowCombinedProof, err := provider.CombineProofs(cellCombinedProofs, coeffs)
		if err != nil {
			return nil, fmt.Errorf("combine row proofs for row %d: %w", row, err)
		}
		rowCommitment, err := provider.Combine(commitments, coeffs)
		if err != nil {
			return nil, fmt.Errorf("combine row commitments for row %d: %w", row, err)
		}

		rowProofs = append(rowProofs, KZGRowProof{
			Row:                uint32(row),
			Columns:            columns,
			Coeffs:             append([]byte(nil), coeffs...),
			CellCombinedProofs: clone2D(cellCombinedProofs),
			CombinedProof:      append([]byte(nil), rowCombinedProof...),
			CombinedCommitment: append([]byte(nil), rowCommitment...),
		})
	}

	return rowProofs, nil
}

func verifyRowProofs(
	rowProofs []KZGRowProof,
	verifiedCols map[uint32][]byte,
	provider cda.KZGProvider,
) error {
	for _, rp := range rowProofs {
		if len(rp.Columns) == 0 {
			return fmt.Errorf("row %d has no columns", rp.Row)
		}
		if len(rp.Columns) != len(rp.Coeffs) {
			return fmt.Errorf("row %d has %d columns but %d coeffs", rp.Row, len(rp.Columns), len(rp.Coeffs))
		}
		if len(rp.Columns) != len(rp.CellCombinedProofs) {
			return fmt.Errorf("row %d has %d columns but %d cell combined proofs", rp.Row, len(rp.Columns), len(rp.CellCombinedProofs))
		}

		commitments := make([]cda.PieceCommitment, 0, len(rp.Columns))
		for _, col := range rp.Columns {
			commitment, ok := verifiedCols[col]
			if !ok {
				return fmt.Errorf("row %d references unverified column %d", rp.Row, col)
			}
			commitments = append(commitments, cda.PieceCommitment(commitment))
		}

		recomputedRowProof, err := provider.CombineProofs(rp.CellCombinedProofs, rp.Coeffs)
		if err != nil {
			return fmt.Errorf("recombine row proofs for row %d: %w", rp.Row, err)
		}
		if !bytes.Equal(recomputedRowProof, rp.CombinedProof) {
			return fmt.Errorf("row %d combined proof mismatch", rp.Row)
		}

		recomputedCommit, err := provider.Combine(commitments, rp.Coeffs)
		if err != nil {
			return fmt.Errorf("recombine row commitments for row %d: %w", rp.Row, err)
		}
		if !bytes.Equal(recomputedCommit, rp.CombinedCommitment) {
			return fmt.Errorf("row %d combined commitment mismatch", rp.Row)
		}

		opening := new(bls12381kzg.OpeningProof)
		if _, err := opening.ReadFrom(bytes.NewReader(rp.CombinedProof)); err != nil {
			return fmt.Errorf("decode row %d combined proof: %w", rp.Row, err)
		}
		claimed := opening.ClaimedValue.Bytes()

		if ok := provider.Verify(cda.PieceCommitment(rp.CombinedCommitment), int(rp.Row), claimed[:], rp.CombinedProof); !ok {
			return fmt.Errorf("pairing verification failed for row %d", rp.Row)
		}
	}

	return nil
}

func deriveRowCoeffs(seed, row, n int) []byte {
	coeffs := make([]byte, n)
	for i := 0; i < n; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%d:%d", seed, row, i)))
		coeff := sum[0]
		if coeff == 0 {
			coeff = 1
		}
		coeffs[i] = coeff
	}
	return coeffs
}

func buildRowBatch(
	rowProofs []KZGRowProof,
	dataRoot []byte,
	namespaceID []byte,
	namespaceVersion uint32,
	provider cda.KZGProvider,
) (*KZGRowBatch, error) {
	if len(rowProofs) == 0 {
		return nil, nil
	}

	transcript := deriveBatchTranscript(dataRoot, namespaceID, namespaceVersion, rowProofs)
	coeffs := deriveBatchCoeffs(transcript, len(rowProofs))

	proofs := make([][]byte, 0, len(rowProofs))
	commits := make([]cda.PieceCommitment, 0, len(rowProofs))
	for _, rp := range rowProofs {
		proofs = append(proofs, rp.CombinedProof)
		commits = append(commits, cda.PieceCommitment(rp.CombinedCommitment))
	}

	combinedProof, err := provider.CombineProofs(proofs, coeffs)
	if err != nil {
		return nil, fmt.Errorf("combine row proofs into batch: %w", err)
	}
	combinedCommitment, err := provider.Combine(commits, coeffs)
	if err != nil {
		return nil, fmt.Errorf("combine row commitments into batch: %w", err)
	}

	return &KZGRowBatch{
		Transcript:         transcript,
		Coeffs:             append([]byte(nil), coeffs...),
		CombinedProof:      append([]byte(nil), combinedProof...),
		CombinedCommitment: append([]byte(nil), combinedCommitment...),
	}, nil
}

func verifyRowBatch(
	rowBatch *KZGRowBatch,
	rowProofs []KZGRowProof,
	dataRoot []byte,
	namespaceID []byte,
	namespaceVersion uint32,
	provider cda.KZGProvider,
) error {
	if rowBatch == nil {
		return nil
	}
	if len(rowProofs) == 0 {
		return fmt.Errorf("row batch provided but no row proofs")
	}

	expectedTranscript := deriveBatchTranscript(dataRoot, namespaceID, namespaceVersion, rowProofs)
	if !bytes.Equal(expectedTranscript, rowBatch.Transcript) {
		return fmt.Errorf("row batch transcript mismatch")
	}

	expectedCoeffs := deriveBatchCoeffs(expectedTranscript, len(rowProofs))
	if !bytes.Equal(expectedCoeffs, rowBatch.Coeffs) {
		return fmt.Errorf("row batch coeffs mismatch")
	}

	proofs := make([][]byte, 0, len(rowProofs))
	commits := make([]cda.PieceCommitment, 0, len(rowProofs))
	for _, rp := range rowProofs {
		proofs = append(proofs, rp.CombinedProof)
		commits = append(commits, cda.PieceCommitment(rp.CombinedCommitment))
	}

	recomputedProof, err := provider.CombineProofs(proofs, rowBatch.Coeffs)
	if err != nil {
		return fmt.Errorf("recombine row proofs in batch verify: %w", err)
	}
	if !bytes.Equal(recomputedProof, rowBatch.CombinedProof) {
		return fmt.Errorf("row batch combined proof mismatch")
	}

	recomputedCommitment, err := provider.Combine(commits, rowBatch.Coeffs)
	if err != nil {
		return fmt.Errorf("recombine row commitments in batch verify: %w", err)
	}
	if !bytes.Equal(recomputedCommitment, rowBatch.CombinedCommitment) {
		return fmt.Errorf("row batch combined commitment mismatch")
	}

	return nil
}

func deriveBatchTranscript(
	dataRoot []byte,
	namespaceID []byte,
	namespaceVersion uint32,
	rowProofs []KZGRowProof,
) []byte {
	h := sha256.New()
	h.Write([]byte("kzg-row-batch-v1"))
	h.Write(dataRoot)
	h.Write(namespaceID)
	h.Write([]byte(fmt.Sprintf(":%d:", namespaceVersion)))
	for _, rp := range rowProofs {
		h.Write([]byte(fmt.Sprintf("r:%d|c:%d|", rp.Row, len(rp.Columns))))
		h.Write(rp.CombinedCommitment)
		h.Write(rp.CombinedProof)
	}
	return h.Sum(nil)
}

func deriveBatchCoeffs(transcript []byte, n int) []byte {
	coeffs := make([]byte, n)
	for i := 0; i < n; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%x:%d", transcript, i)))
		coeff := sum[0]
		if coeff == 0 {
			coeff = 1
		}
		coeffs[i] = coeff
	}
	return coeffs
}

func clone2D(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = append([]byte(nil), in[i]...)
	}
	return out
}
