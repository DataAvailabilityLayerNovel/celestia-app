# Multiproof Implementation Roadmap

## Phase 1: Foundation & Setup

### 1.1 Create `pkg/proof/multiproof_helpers.go`

```go
package proof

import (
	"crypto/rand"
	"fmt"
	
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/cda"
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// RandomCombiningVector generates a random vector of scalars for combining.
// If seed > 0, uses deterministic randomization for testing.
// Otherwise uses cryptographically secure random.
func RandomCombiningVector(size int, seed uint64) ([][]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("invalid vector size: %d", size)
	}
	
	vector := make([][]byte, size)
	
	for i := 0; i < size; i++ {
		var scalar fr.Element
		
		if seed > 0 {
			// Deterministic: derive from seed + index
			// For testing reproducibility
			bytes := make([]byte, 32)
			// Hash(seed || i) into 32 bytes
			// scalar.SetBytes(bytes)
			// TODO: Implement deterministic derivation
		} else {
			// Cryptographic random
			randBytes := make([]byte, 32)
			if _, err := rand.Read(randBytes); err != nil {
				return nil, fmt.Errorf("random generation failed: %w", err)
			}
			scalar.SetBytes(randBytes)
		}
		
		vector[i] = scalar.Bytes()
	}
	
	return vector, nil
}

// CombineCellProofsInRow combines k piece proofs from each cell into one proof per cell.
// For each cell: Σ(coeff[j] * pieceProof[j]) for j in [0, k)
func CombineCellProofsInRow(
	cells []CellProofData,
	codec *rlnc.RLNCCodec,
	provider cda.KZGProvider,
	seed int,
) ([][]byte, error) {
	if len(cells) == 0 {
		return nil, fmt.Errorf("empty cells list")
	}
	
	cellProofs := make([][]byte, len(cells))
	k := codec.MaxChunks()
	
	for i, cell := range cells {
		// Generate coefficients specific to this column
		coeffs := codec.GenerateCoeffsByColSeed(cell.ColumnIndex, seed)
		
		// Combine the k piece proofs with the column-specific coefficients
		combined, err := provider.CombineProofs(cell.PieceProofs, coeffs)
		if err != nil {
			return nil, fmt.Errorf("combine proofs for cell %d: %w", i, err)
		}
		cellProofs[i] = combined
	}
	
	return cellProofs, nil
}

// CombineRowProofs combines multiple cell proofs within a row using vector g.
// Result: Σ(g[i] * cellProof[i]) for i in [0, len(cellProofs))
func CombineRowProofs(
	cellProofs [][]byte,
	combiningVector [][]byte,
	provider cda.KZGProvider,
) ([]byte, error) {
	if len(cellProofs) != len(combiningVector) {
		return nil, fmt.Errorf("cellProofs and combiningVector length mismatch: %d vs %d",
			len(cellProofs), len(combiningVector))
	}
	if len(cellProofs) == 0 {
		return nil, fmt.Errorf("empty proofs list")
	}
	
	// Combine using provider's CombineProofs with combiningVector as coefficients
	rowProof, err := provider.CombineProofs(cellProofs, combiningVector)
	if err != nil {
		return nil, fmt.Errorf("combine row proofs failed: %w", err)
	}
	
	return rowProof, nil
}

// CombineRowCommitments combines column commitments for cells in row using vector g.
// Result: Σ(g[i] * columnComm[affectedColumns[i]])
func CombineRowCommitments(
	columnComms [][]byte,
	affectedColumns []int,
	combiningVector [][]byte,
	provider cda.KZGProvider,
) ([]byte, error) {
	if len(affectedColumns) != len(combiningVector) {
		return nil, fmt.Errorf("affectedColumns and combiningVector length mismatch")
	}
	
	if len(affectedColumns) == 0 {
		return nil, fmt.Errorf("no affected columns")
	}
	
	// Extract the relevant commitments
	selectedComms := make([][]byte, len(affectedColumns))
	for i, col := range affectedColumns {
		if col < 0 || col >= len(columnComms) {
			return nil, fmt.Errorf("column index out of range: %d", col)
		}
		selectedComms[i] = columnComms[col]
	}
	
	// Combine using provider's commitment combination
	// This likely uses scalar multiplication in commitment space
	rowComm, err := provider.CombineCommitments(selectedComms, combiningVector)
	if err != nil {
		return nil, fmt.Errorf("combine row commitments failed: %w", err)
	}
	
	return rowComm, nil
}

// CombineRowValues combines share data from cells using combining vector.
// Result: Σ(g[i] * cellValue[i]) in byteslice arithmetic
// Note: cellValues are typically 32-byte shares, g[i] are 48-byte scalars
func CombineRowValues(
	cellValues [][]byte,
	combiningVector [][]byte,
) ([]byte, error) {
	if len(cellValues) != len(combiningVector) {
		return nil, fmt.Errorf("cellValues and combiningVector length mismatch")
	}
	
	if len(cellValues) == 0 {
		return nil, fmt.Errorf("no cell values")
	}
	
	// For now: use field-based combination
	// Each cellValue is a 32-byte share, combine using field arithmetic
	// Result should be same size as individual share
	
	// TODO: Implement proper field arithmetic for combining shares
	// This may need to use the codec's field operations
	
	// Placeholder: simple concatenation (WRONG - fix later)
	result := make([]byte, 0)
	for i, val := range cellValues {
		// Should do: result += g[i] * val in field arithmetic
		_ = combiningVector[i] // use combiningVector
		result = append(result, val...)
	}
	
	return result, nil
}

// CellProofData groups data for a single cell in a row
type CellProofData struct {
	ColumnIndex int      // Column index in EDS
	PieceProofs [][]byte // k piece opening proofs
	ShareData   []byte   // 32-byte share data
}
```

### 1.2 Update Data Structures

**File: `pkg/proof/kzg_range_proof.go`**

```go
// Add to KZGRangeProof struct:

type KZGRangeProof struct {
	// ... existing fields ...
	
	// Multiproof path (alternative to CellProofs)
	RowProofs []KZGRowProof
	UseMultiproof bool
}

// New data structure for row-based proofs
type KZGRowProof struct {
	Row              uint32          // Row index in ODS
	AffectedColumns  []uint32        // Which columns in this row are in range
	ColumnValues     [][]byte        // Share data for each affected cell
	CombiningVector  [][]byte        // Random vector g for combining
	RowValue         []byte          // Combined row value: Σ g[i]*columnValues[i]
	RowProof         []byte          // Combined KZG proof for row
	RowCommitment    []byte          // Combined commitment: Σ g[i]*colComm[cols[i]]
	ColumnProofs     [][]byte        // Merkle proofs linking each column to root
}
```

---

## Phase 2: Build Path

### 2.1 Implement Builder Function

**File: `pkg/proof/kzg_range_proof.go`** (add new function)

```go
// NewKZGRangeProofMultiproof builds a multiproof version of range proof.
// This combines cells within each row for more efficient proofs.
func NewKZGRangeProofMultiproof(
	eds *rsmt2d.ExtendedDataSquare,
	dah *da.DataAvailabilityHeader,
	namespace share.Namespace,
	codec *rlnc.RLNCCodec,
	provider cda.KZGProvider,
	seed int,
	multiproofSeed uint64, // for random vector generation
) (*KZGRangeProof, error) {
	if eds == nil || dah == nil || codec == nil || provider == nil {
		return nil, fmt.Errorf("nil input provided")
	}

	// Step 1: Get namespace range (reuse existing logic)
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

	// Step 2: Get all affected cells (reuse existing logic)
	affectedCols := make(map[int]struct{})
	cellsByRow := make(map[int][]int) // row -> []column indices
	
	for idx := nsRange.Start; idx < nsRange.End; idx++ {
		row := idx / squareSize
		col := idx % squareSize
		if row < 0 || row >= squareSize || col < 0 || col >= squareSize {
			return nil, fmt.Errorf("cell index %d maps out of ODS bounds", idx)
		}
		affectedCols[col] = struct{}{}
		cellsByRow[row] = append(cellsByRow[row], col)
	}

	// Build column merkle proofs (reuse existing logic)
	_, allMerkleProofs := merkle.ProofsFromByteSlices(dah.ColumnComm)
	
	columnProofs := make([]KZGColumnProof, 0, len(affectedCols))
	cols := make([]int, 0, len(affectedCols))
	for col := range affectedCols {
		cols = append(cols, col)
	}
	sort.Ints(cols)
	
	for _, col := range cols {
		if col >= len(dah.ColumnComm) {
			return nil, fmt.Errorf("column %d out of header commitment bounds", col)
		}
		p := allMerkleProofs[col]
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

	// Get all piece proofs once
	allOpenProofs, err := cda.ComputeOpenProofCells(codec, eds, provider)
	if err != nil {
		return nil, err
	}

	// Step 3: Build multiproof for each row
	rowProofs := make([]KZGRowProof, 0, len(cellsByRow))
	
	for rowIdx := 0; rowIdx < len(cellsByRow); rowIdx++ {
		cellColumns, ok := cellsByRow[rowIdx]
		if !ok {
			continue // This row not affected
		}
		sort.Ints(cellColumns)

		// Step 3a: Generate random combining vector
		g, err := RandomCombiningVector(len(cellColumns), multiproofSeed)
		if err != nil {
			return nil, fmt.Errorf("generate combining vector for row %d: %w", rowIdx, err)
		}

		// Step 3b: Collect piece proofs and share data for each cell
		cellProofData := make([]CellProofData, len(cellColumns))
		cellValues := make([][]byte, len(cellColumns))
		
		rowData := eds.Row(uint(rowIdx))
		for i, col := range cellColumns {
			if col >= len(rowData) {
				return nil, fmt.Errorf("column %d out of row width", col)
			}

			// Get piece proofs
			proofStart := ((rowIdx * width) + col) * k
			if proofStart+k > len(allOpenProofs) {
				return nil, fmt.Errorf("open proof slice out of bounds for row=%d col=%d", rowIdx, col)
			}

			pieceProofs := make([][]byte, k)
			for j := 0; j < k; j++ {
				pieceProofs[j] = append([]byte(nil), allOpenProofs[proofStart+j]...)
			}

			cellProofData[i] = CellProofData{
				ColumnIndex: col,
				PieceProofs: pieceProofs,
				ShareData:   append([]byte(nil), rowData[col]...),
			}
			cellValues[i] = append([]byte(nil), rowData[col]...)
		}

		// Step 3c: Combine piece proofs into cell proofs
		cellProofs, err := CombineCellProofsInRow(cellProofData, codec, provider, seed)
		if err != nil {
			return nil, fmt.Errorf("combine cell proofs for row %d: %w", rowIdx, err)
		}

		// Step 3d: Combine cell proofs into row proof
		rowProof, err := CombineRowProofs(cellProofs, g, provider)
		if err != nil {
			return nil, fmt.Errorf("combine row proofs for row %d: %w", rowIdx, err)
		}

		// Step 3e: Combine row commitments
		columnCommsForRow := dah.ColumnComm
		columnInduesForRow := make([]int, len(cellColumns))
		for i, col := range cellColumns {
			columnInduesForRow[i] = col
		}
		
		rowComm, err := CombineRowCommitments(columnCommsForRow, columnInduesForRow, g, provider)
		if err != nil {
			return nil, fmt.Errorf("combine row commitments for row %d: %w", rowIdx, err)
		}

		// Step 3f: Combine row values
		rowValue, err := CombineRowValues(cellValues, g)
		if err != nil {
			return nil, fmt.Errorf("combine row values for row %d: %w", rowIdx, err)
		}

		// Step 3g: Get merkle proofs for columns in this row
		rowColumnProofs := make([][]byte, len(cellColumns))
		for i, col := range cellColumns {
			p := allMerkleProofs[col]
			rowColumnProofs[i] = p.LeafHash
		}

		rowProofs = append(rowProofs, KZGRowProof{
			Row:             uint32(rowIdx),
			AffectedColumns: convertToUint32(cellColumns),
			ColumnValues:    cellValues,
			CombiningVector: g,
			RowValue:        rowValue,
			RowProof:        rowProof,
			RowCommitment:   rowComm,
			ColumnProofs:    rowColumnProofs,
		})
	}

	// Step 4: Return multiproof
	return &KZGRangeProof{
		NamespaceID:      append([]byte(nil), namespace.ID()...),
		NamespaceVersion: uint32(namespace.Version()),
		StartCell:        uint32(nsRange.Start),
		EndCell:          uint32(nsRange.End),
		DataRoot:         append([]byte(nil), dah.Hash()...),
		Width:            uint32(width),
		MaxChunks:        uint32(k),
		Seed:             seed,
		ColumnProofs:     columnProofs,
		RowProofs:        rowProofs,
		UseMultiproof:    true,
	}, nil
}

func convertToUint32(ints []int) []uint32 {
	result := make([]uint32, len(ints))
	for i, v := range ints {
		result[i] = uint32(v)
	}
	return result
}
```

---

## Phase 3: Verify Path

### 3.1 Implement Verifier Function

**File: `pkg/proof/kzg_range_proof.go`** (add new function)

```go
// VerifyKZGRangeProofMultiproof verifies a multiproof version.
func VerifyKZGRangeProofMultiproof(
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
	if int(proof.Width) == 0 {
		return fmt.Errorf("invalid proof width")
	}

	// Step 1: Verify column merkle proofs
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

	// Step 2: Verify each row proof
	for _, rowProof := range proof.RowProofs {
		// Step 2a: Reconstruct row commitment
		selectedComms := make([][]byte, len(rowProof.AffectedColumns))
		for i, col := range rowProof.AffectedColumns {
			if int(col) >= len(dah.ColumnComm) {
				return fmt.Errorf("column %d out of header bounds", col)
			}
			selectedComms[i] = dah.ColumnComm[col]
		}

		reconstructedComm, err := CombineRowCommitments(
			dah.ColumnComm,
			convertToInt(rowProof.AffectedColumns),
			rowProof.CombiningVector,
			provider,
		)
		if err != nil {
			return fmt.Errorf("reconstruct row commitment for row %d: %w", rowProof.Row, err)
		}

		if !bytes.Equal(reconstructedComm, rowProof.RowCommitment) {
			return fmt.Errorf("row %d commitment mismatch", rowProof.Row)
		}

		// Step 2b: Verify merkle proofs for columns in this row
		for i, col := range rowProof.AffectedColumns {
			if int(col) >= len(dah.ColumnComm) {
				return fmt.Errorf("column %d out of header bounds", col)
			}
			if !bytes.Equal(rowProof.ColumnProofs[i], dah.ColumnComm[col]) {
				return fmt.Errorf("row %d column %d merkle proof mismatch", rowProof.Row, col)
			}
		}

		// Step 2c: Reconstruct row value
		reconstructedValue, err := CombineRowValues(
			rowProof.ColumnValues,
			rowProof.CombiningVector,
		)
		if err != nil {
			return fmt.Errorf("reconstruct row value for row %d: %w", rowProof.Row, err)
		}

		if !bytes.Equal(reconstructedValue, rowProof.RowValue) {
			return fmt.Errorf("row %d value mismatch", rowProof.Row)
		}

		// Step 2d: Verify KZG proof
		if ok := provider.Verify(
			cda.PieceCommitment(rowProof.RowCommitment),
			int(rowProof.Row),
			rowProof.RowValue,
			rowProof.RowProof,
		); !ok {
			return fmt.Errorf("KZG verification failed for row %d", rowProof.Row)
		}
	}

	return nil
}

func convertToInt(uints []uint32) []int {
	result := make([]int, len(uints))
	for i, v := range uints {
		result[i] = int(v)
	}
	return result
}
```

### 3.2 Update Main Verify Function

**File: `pkg/proof/kzg_range_proof.go`** (modify existing function)

```go
// VerifyKZGRangeProof routes to appropriate verifier
func VerifyKZGRangeProof(
	proof *KZGRangeProof,
	dah *da.DataAvailabilityHeader,
	codec *rlnc.RLNCCodec,
	provider cda.KZGProvider,
) error {
	if proof.UseMultiproof {
		return VerifyKZGRangeProofMultiproof(proof, dah, codec, provider)
	}
	// ... existing single-cell verification ...
}
```

---

## Phase 4: Testing

### 4.1 Create Test Suite

**File: `pkg/proof/multiproof_test.go`** (new)

```go
package proof_test

import (
	"testing"
	"github.com/stretchr/testify/require"
	// ... other imports ...
)

const multiproofSeed uint64 = 12345

// TestMultiproofBuildAndVerify tests basic multiproof build and verify
func TestMultiproofBuildAndVerify(t *testing.T) {
	// Create EDS and DAH
	// Build multiproof
	// Verify multiproof
	// Assert success
}

// TestMultiproofDeterministic tests deterministic combining vector
func TestMultiproofDeterministic(t *testing.T) {
	// Build two multiproofs with same seed
	// Assert they produce identical results
}

// TestMultiproofCompressionRatio tests proof size savings
func TestMultiproofCompressionRatio(t *testing.T) {
	// Build single-cell proof
	// Build multiproof
	// Compare sizes
	// Assert multiproof is smaller
}

// TestMultiproofPartialRange tests range spanning multiple rows
func TestMultiproofPartialRange(t *testing.T) {
	// Create range spanning 3 rows
	// Build multiproof
	// Assert 3 row proofs
	// Verify
}

// TestMultiproofTamperedValue tests security
func TestMultiproofTamperedValue(t *testing.T) {
	// Build multiproof
	// Tamper with row value
	// Verify should fail
}

// TestMultiproofTamperedCommitment tests security
func TestMultiproofTamperedCommitment(t *testing.T) {
	// Build multiproof
	// Tamper with row commitment
	// Verify should fail
}
```

---

## Implementation Checklist

- [ ] **Week 1**
  - [ ] Create `multiproof_helpers.go` skeleton
  - [ ] Implement `RandomCombiningVector`
  - [ ] Implement `CombineCellProofsInRow`
  - [ ] Implement `CombineRowProofs`
  - [ ] Implement `CombineRowCommitments`
  - [ ] Implement `CombineRowValues` (field arithmetic)
  - [ ] Unit test helpers

- [ ] **Week 2**
  - [ ] Create `KZGRowProof` data structure
  - [ ] Implement `NewKZGRangeProofMultiproof` builder
  - [ ] Implement `VerifyKZGRangeProofMultiproof` verifier
  - [ ] Integration tests

- [ ] **Week 3**
  - [ ] Edge case testing
  - [ ] Security testing (tampering scenarios)
  - [ ] Performance benchmarks
  - [ ] Compression ratio analysis

- [ ] **Week 4**
  - [ ] Integration with existing API
  - [ ] Documentation
  - [ ] Code review & cleanup

---

## Dependencies & Requirements

### New Package Dependencies
- `crypto/rand` - for random vector generation (already available)

### Existing Dependencies Used
- `github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/cda` - KZG provider
- `github.com/consensys/gnark-crypto` - Field arithmetic for combining values

### API Requirements from cda.KZGProvider
- `CombineProofs(proofs [][]byte, combining_vector [][]byte) ([]byte, error)`
- `CombineCommitments(comms [][]byte, combining_vector [][]byte) ([]byte, error)` - **May need to add**
- `Verify(commitment []byte, row int, value []byte, proof []byte) bool`

### Open Questions
1. Does `cda.KZGProvider` have `CombineCommitments` method?
   - If not, may need to use scalar multiplication directly
   - Or extend the provider interface

2. How to properly combine share values in field arithmetic?
   - Each share is 32 bytes
   - Each scalar is 48 bytes (BLS12-381 field)
   - Need field-based inner product

3. Random vector representation?
   - Should match codec's coefficient format
   - Likely 48-byte scalars in Fr field

---

## Success Metrics

✅ All tests passing
✅ Multiproof size < 50% of single-cell proof size for ranges > 4 cells  
✅ Verify time < 2× build time per row
✅ No security regressions (tampering detected)
✅ Deterministic reproducibility with seed
