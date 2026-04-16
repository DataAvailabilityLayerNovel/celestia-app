# Multiproof for Range Proofs - Design & Implementation Plan

## 1. Conceptual Overview

### Problem with Current Approach
Currently, `KZGRangeProof` contains **one proof per cell** in the range:


### Multiproof Solution: Three-Level Hierarchical Combining

**Level 1**: Combine k piece proofs per cell (using column-specific coefficients)
- Input: k piece proofs for one cell
- Coeffs: `GenerateCoeffsByColSeed(column, seed)`
- Output: 1 cell proof

**Level 2**: Combine cell proofs within each row (using random vector g_row)
- Input: N cell proofs in one row
- Vector: Random g_row (N scalars)
- Output: 1 row proof + 1 row commitment per row

**Level 3** (NEW): Combine row proofs across all rows (using random vector g_final)
- Input: R row proofs and R row commitments from all affected rows
- Vector: Random g_final (R scalars)
- Output: **1 final proof + 1 final commitment for entire range**
- Result: **O(1) proof** instead of O(cells) or O(rows)!

### Key Insight
Hierarchical combining leverages KZG homomorphism:
```
proof_final = Σ g_final[i] * rowProof[i]
comm_final = Σ g_final[i] * rowComm[i]
value_final = Σ g_final[i] * rowValue[i]
```
Verify once: `provider.Verify(comm_final, representative_row, value_final, proof_final)`
---

## 2. Cryptographic Foundation


### Level 2: Per-Row Combining
```
Given cells in row at columns [c1, c2, ..., cN]:
rowComm = Σ g_row[i] * colComm[ci]
rowProof = Σ g_row[i] * cellProof[i]
rowValue = Σ g_row[i] * cellValue[i]

Verification:
provider.Verify(rowComm, row_index, rowValue, rowProof) = true
```

### Level 3: Final Combining Across Rows
```
Given R row proofs and commitments:
finalComm = Σ g_final[i] * rowComm[i]     // Combine row commitments
finalProof = Σ g_final[i] * rowProof[i]   // Combine row proofs
finalValue = Σ g_final[i] * rowValue[i]   // Combine row values

Verification:
provider.Verify(finalComm, representative_row, finalValue, finalProof) = true

Note: representative_row can be any row (protocol soundness not affected)
```
---

## 3. Data Structure Changes

### Current KZGRangeProof
```go
type KZGRangeProof struct {
    NamespaceID, NamespaceVersion uint32
    StartCell, EndCell uint32
    DataRoot []byte
    Width uint32
    MaxChunks uint32
    Seed int
    
    ColumnProofs []KZGColumnProof  // Phase 1: column inclusion proofs
    CellProofs   []KZGCellProof    // Phase 2: per-cell opening proofs (N cells)
}
```

### Proposed: Add Multiproof

```go
type KZGRangeProof struct {
   // ... existing fields ...
    
   // ADDED: Multiproof phases
   RowProofs      []KZGRowProof       // Level 2: One per affected row
   CombinedProof  *KZGCombinedProof   // Level 3: Single proof for entire range
}

// Level 2: Per-row combining
type KZGRowProof struct {
   Row              uint32        // Row index in ODS
   AffectedColumns  []uint32      // Columns in this row that are in range
   ColumnValues     [][]byte      // Share data for each affected cell
   RowCombinVector  [][]byte      // Random vector g_row (per-row combining)
   RowValue         []byte        // Σ g_row[i] * cellValue[i]
   RowProof         []byte        // Single opening proof for this row
   RowCommitment    []byte        // Σ g_row[i] * colComm[affectedColumns[i]]
   ColumnProofs     [][]byte      // Merkle proofs for each affected column
}

// Level 3: Final combining across all rows
type KZGCombinedProof struct {
   RowIndices       []uint32      // Which rows are combined
   FinalCombinVector [][]byte     // Random vector g_final (R scalars for R rows)
    
   FinalValue       []byte        // Σ g_final[i] * rowValue[i]
   FinalProof       []byte        // Σ g_final[i] * rowProof[i]
   FinalCommitment  []byte        // Σ g_final[i] * rowComm[i]
    
   // For reconstruction: need to combine row commitments with g_final
   RowCommitments   [][]byte      // []rowComm[i] for each row
}
```
---

## 4. Implementation Phases

### Phase A: Helper Functions (Week 1)
**File: `pkg/proof/multiproof_helpers.go`** (new)

```go
// RandomCombiningVector generates random scalar vector of given length
func RandomCombiningVector(size int, codec *rlnc.RLNCCodec) ([][]byte, error)

// CombineCellProofsInRow combines k piece proofs from each cell into one proof per cell
func CombineCellProofsInRow(
    cellsInRow []CellProofData,  // data for each cell in row
    codec *rlnc.RLNCCodec,
    provider cda.KZGProvider,
    seed int,
) ([][]byte, error)  // Returns one combined proof per cell

// CombineRowProofs combines multiple cell proofs within a row using vector g
func CombineRowProofs(
    cellProofs [][]byte,       // Combined proof for each cell (k=codec.MaxChunks())
    combiningVector [][]byte,  // Random vector g
    provider cda.KZGProvider,
) ([]byte, error)  // Returns single row proof

// CombineRowCommitments combines column commitments for cells in row
func CombineRowCommitments(
    columnComms [][]byte,      // Each column's commitment
    affectedCols []int,        // Which columns are affected
    combiningVector [][]byte,  // Random vector g
    provider cda.KZGProvider,
) ([]byte, error)  // Returns combined row commitment

// CombineRowValues combines share data from cells using combining vector
func CombineRowValues(
    cellValues [][]byte,       // Share data for each cell
    combiningVector [][]byte,  // Random vector g
) ([]byte, error)  // Returns combined row value
```

### Phase B: Build Path (Week 2)

**File: `pkg/proof/kzg_range_proof.go`** (extend existing)

New functions:
```go
// Level 2: Per-row combining
func NewKZGRowProof(
   eds *rsmt2d.ExtendedDataSquare,
   dah *da.DataAvailabilityHeader,
   rowIndex int,
   cellsInRow []CellReference,
   codec *rlnc.RLNCCodec,
   provider cda.KZGProvider,
   seed int,
   rowCombinSeed uint64,
) (*KZGRowProof, error) {
   // 1. Generate random combining vector g_row
   // 2. For each cell: combine k piece proofs → cell proof (using seed)
   // 3. Combine all cell proofs → row proof (using g_row)
   // 4. Combine row values → row value (using g_row)
   // 5. Combine column commitments → row commitment (using g_row)
   // 6. Collect merkle proofs for columns
}

// Level 3: Final combining across rows
func NewKZGCombinedProof(
   rowProofs []KZGRowProof,
   dah *da.DataAvailabilityHeader,
   provider cda.KZGProvider,
   finalCombinSeed uint64,
) (*KZGCombinedProof, error) {
   // 1. Generate random combining vector g_final
   // 2. Extract row commitments from each row proof
   // 3. Combine row commitments → final commitment (using g_final)
   // 4. Combine row proofs → final proof (using g_final)
   // 5. Combine row values → final value (using g_final)
}

// Complete build function
func NewKZGRangeProofMultiproof(
   eds *rsmt2d.ExtendedDataSquare,
   dah *da.DataAvailabilityHeader,
   namespace share.Namespace,
   codec *rlnc.RLNCCodec,
   provider cda.KZGProvider,
   seed int,
) (*KZGRangeProof, error) {
   // 1. Parse namespace and group cells by row
   // 2. For each row: NewKZGRowProof → get RowProofs
   // 3. NewKZGCombinedProof → get single final proof
   // 4. Return KZGRangeProof with RowProofs + CombinedProof
}
```
**Algorithm: Build Per-Row Multiproof**
```
Input: EDS, DAH, range of cells [start, end), row_index
Output: KZGRowProof

1. Find all cells in this row within range
2. Extract their column indices: cols = [c1, c2, ..., cN]
3. Generate g ← RandomCombiningVector(N, codec)

4. For each cell i in row:
   a. Get k piece proofs from EDS
   b. Get coeffs ← GenerateCoeffsByColSeed(cols[i], seed)
   c. cellProof[i] = Combine(piecesProofs[i], coeffs)

5. rowProof = Combine(cellProofs, g)

6. For each column index c in cols:
   rowComm_contribution = g[i] * columnComm[c]
7. rowComm = Sum(rowComm_contribution)

8. rowValue = Combine(cellValues, g)

9. Return KZGRowProof{
     Row: row_index,
     AffectedColumns: cols,
     ColumnValues: [cellValues for each cell],
     CombiningVector: g,
     RowValue: rowValue,
     RowProof: rowProof,
     RowCommitment: rowComm,
     ColumnProofs: [merkle proofs for cols],
   }
```

### Phase C: Verify Path (Week 2)

**File: `pkg/proof/kzg_range_proof.go`** (extend existing)

New functions:
```go
// Verify Level 2: Per-row proofs
func VerifyKZGRowProof(
   rowProof *KZGRowProof,
   dah *da.DataAvailabilityHeader,
   codec *rlnc.RLNCCodec,
   provider cda.KZGProvider,
) error {
   // 1. Verify merkle proofs for columns in this row
   // 2. Reconstruct row commitment from column commitments
   // 3. Verify row commitment matches stored value
   // 4. Reconstruct row value from column values and g_row
   // 5. Verify row value matches stored value
   // 6. Verify KZG proof for this row
}

// Verify Level 3: Final combined proof
func VerifyCombinedProof(
   combined *KZGCombinedProof,
   rowProofs []KZGRowProof,
   provider cda.KZGProvider,
) error {
   // 1. Extract row commitments from rowProofs
   // 2. Reconstruct final commitment from row commitments + g_final
   // 3. Verify final commitment matches stored value
   // 4. Reconstruct final value from row values + g_final
   // 5. Verify final value matches stored value
   // 6. Verify KZG proof for final combined proof
}

// Complete verify function
func VerifyKZGRangeProofMultiproof(
   proof *KZGRangeProof,
   dah *da.DataAvailabilityHeader,
   codec *rlnc.RLNCCodec,
   provider cda.KZGProvider,
) error {
   // 1. Verify column merkle proofs (Phase 1)
   // 2. Verify each row proof (Level 2)
   // 3. Verify final combined proof (Level 3) → single check!
}
```
**Algorithm: Verify Per-Row Multiproof**
```
Input: KZGRowProof, DAH, codec, provider
Output: error or nil

1. Get affected column indices: cols = rowProof.AffectedColumns
2. Get combining vector: g = rowProof.CombiningVector
3. Verify Merkle proofs:
   For each col in cols:
     Verify merkle(dah.ColumnComm[col], proof) included in dah.Hash()

4. Reconstruct row commitment:
   rowComm = Sum(g[i] * dah.ColumnComm[cols[i]] for i in 0..N-1)

5. Verify row commitment matches stored value:
   If rowComm != rowProof.RowCommitment then error

6. Reconstruct column values:
   For each cell in rowProof.ColumnValues:
     Verify it's valid share data

7. Verify combined row proof:
   provider.Verify(rowComm, rowIndex, rowProof.RowValue, rowProof.RowProof)

8. Return nil if all checks pass
```

### Phase D: Testing (Week 3)
**File: `pkg/proof/multiproof_test.go`** (new)

```go
func TestMultiproofBuildAndVerify(t *testing.T)
func TestMultiproofDeterministic(t *testing.T)
func TestMultiproofCompression(t *testing.T)  // Compare size vs single-cell proofs
func TestMultiproofPartialRange(t *testing.T)  // Range spanning multiple rows
func TestMultiproofSingleCell(t *testing.T)    // Edge case: one cell per row
func TestMultiproofTamperedCommitment(t *testing.T)
func TestMultiproofTamperedValue(t *testing.T)
func TestMultiproofInvalidCombiningVector(t *testing.T)
```

### Phase E: Integration & Optimization (Week 4)
- Add flag to `NewKZGRangeProofFromEDS` to enable multiproof mode
- Performance benchmarks (`BenchmarkMultiproofBuild`, `BenchmarkMultiproofVerify`)
- Proof size comparison analysis
- Documentation updates

---

## 5. Detailed Algorithms

### 5.1 Build: Combining Cell Proofs Within Row
```
Input: cells in row [c1, c2, ..., cN] at positions [cols[1], cols[2], ..., cols[N]]
       EDS, codec, provider, seed

1. For each cell i:
   a. Get share data: shareData[i] = eds.Row(row)[cols[i]]
   b. Get all k piece proofs: piecesProofs[i][j] = eds.GetPieceProof(row, cols[i], j)
   c. Generate combining coefficients: coeffs = GenerateCoeffsByColSeed(cols[i], seed)
   d. Combine piece proofs: cellProof[i] = provider.CombineProofs(piecesProofs[i], coeffs)

2. Generate random vector: g ← RandomCombiningVector(N, codec)

3. Combine cell proofs: rowProof = provider.CombineProofs(cellProofs, g)

4. Combine share values: rowValue = CombineValues(shareData, g)

5. Reconstruct row commitment:
   For i in [0, N):
     contribution[i] = g[i] * dah.ColumnComm[cols[i]]
   rowComm = Sum(contribution[i])

Output: KZGRowProof{
  affectedColumns: cols,
  combiningVector: g,
  rowProof: rowProof,
  rowCommitment: rowComm,
  rowValue: rowValue,
  columnValues: shareData,
}
```

### 5.2 Verify: Checking Correctness
```
Input: KZGRowProof, DAH, codec, provider

1. Extract: cols = rowProof.AffectedColumns, g = rowProof.CombiningVector
2. Recompute row commitment:
   rowComm' = Sum(g[i] * dah.ColumnComm[cols[i]])
3. Compare: if rowComm' != rowProof.RowCommitment then FAIL("commitment mismatch")

4. Verify Merkle proofs (each column included in header root):
   For each i, col in cols:
     if NOT VerifyMerkle(dah.ColumnComm[col], rowProof.ColumnProofs[i], header_root) then
       FAIL("column " + col + " not in header")

5. Reconstruct row value:
   rowValue' = CombineValues(rowProof.ColumnValues, g)
6. Compare: if rowValue' != rowProof.RowValue then FAIL("value mismatch")

7. Verify KZG proof:
   if NOT provider.Verify(rowComm, row_index, rowValue, rowProof.RowProof) then
     FAIL("KZG verification failed")

8. Return nil (all checks passed)
```

---

## 6. Implementation Details

### 6.1 Random Combining Vector Generation
```go
// Should use deterministic random (seeded) for testing
// In production: crypto/rand for security
func RandomCombiningVector(size int, codec *rlnc.RLNCCodec) ([][]byte, error) {
    // Generate size scalar values
    // Return as byte representations (48 bytes each for BLS12-381 scalars)
    // Ensure they're field elements
}
```

### 6.2 Combining Values
```go
func CombineValues(values [][]byte, g [][]byte) ([]byte, error) {
    // Compute: result = Σ g[i] * values[i]
    // values[i] are 32-byte shares
    // g[i] are 48-byte field elements
    // Use field arithmetic for combination
}
```

### 6.3 Combining Commitments
```go
func CombineCommitments(comms [][]byte, g [][]byte, provider cda.KZGProvider) ([]byte, error) {
    // Compute: result = Σ g[i] * comm[i]
    // Both comm[i] and g[i] are point/scalar pairs
    // Use point scalar multiplication in the KZG provider's group
}
```

---

## 7. File Structure

```
pkg/proof/
├── kzg_range_proof.go          (MODIFY: add NewKZGRangeProofMultiproof, VerifyMultiproof)
├── multiproof_helpers.go       (CREATE: new - helper functions)
├── multiproof_test.go          (CREATE: new - test suite)
├── multiproof_bench_test.go    (CREATE: optional - benchmarks)
└── MULTIPROOF_DESIGN.md        (CREATE: this file)
```

---

## 8. Testing Strategy

### Unit Tests (multiproof_test.go)
1. **Correctness**
   - Build and verify single row
   - Build and verify multi-row range
   - Deterministic combination (same inputs → same output)
   
2. **Edge Cases**
   - Single cell in row
   - Multiple cells in row
   - Range spanning 1 row vs N rows
   - Full square coverage
   
3. **Failure Cases**
   - Tampered commitment
   - Tampered combining vector
   - Tampered row value
   - Invalid merkle proofs
   
4. **Comparison**
   - Multiproof result vs single-cell proof result
   - Proof size compression ratio
   - Build/verify performance

---

## 9. Integration Timeline

| Week | Phase | Key Deliverables |
|------|-------|-----------------|
| 1 | Helper Functions | multiproof_helpers.go complete, all helpers tested |
| 2 | Build & Verify | NewKZGRangeProofMultiproof, VerifyKZGRangeProofMultiproof working |
| 2 | Testing | Core test cases passing (20+ tests) |
| 3 | Refinement | Edge cases handled, performance benchmarks |
| 4 | Integration | Flag in existing API, docs updated |

---

## 10. Open Questions & Decisions

- **Random Vector Seeding**: Deterministic (for testing) or random (for production)?  
  → *Decision*: Add `multiproofSeed` parameter for reproducibility, use crypto/rand if seed=0
  
- **Proof Size Overhead**: Storing combining vector `g` adds ~N*48 bytes per row
  → *Optimization*: Consider deriving `g` deterministically from (row_index, namespace) instead of random
  
- **Merkle Proof Inclusion**: Do we need per-column merkle proofs in RowProof?
  → *Consideration*: Could batch verify all columns at once
  
- **Backwards Compatibility**: Keep old format or replace entirely?
  → *Decision*: Support both paths via `UseMultiproof` flag during transition

---

## 11. Success Criteria

✅ **Correctness**: All tests pass, verification always succeeds for valid proofs  
✅ **Compression**: Proofs for range >1 row are smaller than N individual cell proofs  
✅ **Performance**: Verify time < 2x build time per row  
✅ **Security**: Random combining vector is cryptographically independent  
✅ **Integration**: Existing code still works, multiproof is opt-in via flag
