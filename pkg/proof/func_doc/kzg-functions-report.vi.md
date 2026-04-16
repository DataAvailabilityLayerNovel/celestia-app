# Tong hop Ham Da Xay Dung Va Luong Da Kiem Thu KZG

Ngay cap nhat: 2026-04-16

## 1) Pham vi

Tai lieu nay tong hop implementation KZG range-proof hien dang su dung trong luong moi tai `pkg/proof/kzg_range_proof.go` va test tuong ung.

Luu y:

- Luong mac dinh cua toan app van co legacy path.
- Tai lieu nay chi mo ta phan KZG range-proof da duoc noi va test trong package proof.

## 2) Ham/chuc nang da trien khai

File chinh: `pkg/proof/kzg_range_proof.go`

### 2.1 Wire format

- `KZGRangeProof`
  - `NamespaceID`, `NamespaceVersion`
  - `StartCell`, `EndCell`
  - `DataRoot`, `Width`, `MaxChunks`, `Seed`
  - `ColumnProofs`
  - `CellProofs`
  - `RowProofs` (muc M1)
  - `RowBatch` (muc M2)

- `KZGColumnProof`
  - `Column`, `Commitment`, `Proof` (Merkle proof tren `dah.ColumnComm`)

- `KZGCellProof`
  - `Row`, `Column`, `ShareData`, `PieceOpenProofs`

- `KZGRowProof`
  - `Row`, `Columns`, `Coeffs`
  - `CellCombinedProofs`
  - `CombinedProof`, `CombinedCommitment`

- `KZGRowBatch`
  - `Transcript`, `Coeffs`
  - `CombinedProof`, `CombinedCommitment`

### 2.2 Build proof

- `NewKZGRangeProofFromEDS(eds, dah, namespace, codec, provider, seed)`
  - Lay namespace range tu `dah.NamespaceRange`
  - Build `ColumnProofs` tu `merkle.ProofsFromByteSlices(dah.ColumnComm)`
  - Build `CellProofs` tu `cda.ComputeOpenProofCells`
  - Build `RowProofs` qua `buildRowProofs`
  - Build `RowBatch` qua `buildRowBatch`

- `buildRowProofs(...)`
  - Gom cell theo row
  - Moi cell: combine piece proofs theo `codec.GenerateCoeffsByColSeed(col, seed)`
  - Moi row: combine lai cell proofs -> `CombinedProof`, commitments -> `CombinedCommitment`

- `buildRowBatch(...)`
  - Tao transcript deterministic tu `(DataRoot, Namespace, RowProofs)`
  - Sinh coeffs batch tu transcript
  - Combine tat ca `row.CombinedProof` va `row.CombinedCommitment`

### 2.3 Verify proof

- `VerifyKZGRangeProof(...)`
  - Pha 1: verify column commitment inclusion len root
  - Neu co `RowProofs`:
    - Verify row-batch consistency (`verifyRowBatch`) neu co payload
    - Verify cryptographic tung row (`verifyRowProofs`)
  - Neu khong co row proofs: fallback verify per-cell

- `verifyRowProofs(...)`
  - Recombine row proof/commitment de check consistency
  - Pairing verify tren moi row bang `provider.Verify`

- `verifyRowBatch(...)`
  - Recompute transcript + coeffs
  - Recombine lai proof/commitment cap row va doi chieu voi payload batch

### 2.4 Helper

- `deriveRowCoeffs(...)`
- `deriveBatchTranscript(...)`
- `deriveBatchCoeffs(...)`
- `clone2D(...)`

## 3) Primitive tu cda/codec dang su dung

- `cda.ComputeAndSetKateCommitments`
- `cda.ComputeOpenProofCells`
- `codec.GenerateCoeffsByColSeed`
- `provider.Combine`
- `provider.CombineProofs`
- `provider.Verify`

## 4) Luong test da co

### 4.1 Test co san (file `pkg/proof/proof_test.go`)

- `TestKateCommitmentsAndColumnProofs`
- `TestKateRootRequiresCommitments`
- `TestColumnCommitmentDeterministicCombine`
- `TestPerCellPairingVerificationFlow`
- `TestBuildAndVerifyKZGRangeProof`
- `TestVerifyKZGRangeProofRejectsTamperedColumnCommitment`
- `TestVerifyKZGRangeProofRejectsTamperedRowProof`
- `TestVerifyKZGRangeProofRejectsTamperedRowBatch`

### 4.2 Test rieng cho row/batch (file `pkg/proof/kzg_range_proof_row_batch_test.go`)

- Golden:
  - single-row range pass
  - multi-row range pass
- Negative:
  - tamper row commitment -> fail
  - tamper row proof -> fail
  - tamper row batch transcript -> fail
- Determinism:
  - build 2 lan cung input, payload row/row-batch giong nhau

## 5) Ket luan hien trang

- M1 (row-level aggregation) da xong.
- M2 (row-batch transcript + recombine consistency) da xong.
- M4 phan correctness test (golden/negative/determinism) da xong.
- `go test ./pkg/proof -count=1` dang pass.

## 6) Gioi han hien tai

- Chua co primitive public cho true multi-pairing batch verify across rows trong `cda.KZGProvider`.
- Vi vay hien tai van verify pairing theo tung row sau khi pass row-batch consistency.

## 7) Viec tiep theo

- Neu can, bo sung benchmark (khong anh huong correctness):
  - verify tung row
  - verify row-batch consistency
  - so sanh chi phi
