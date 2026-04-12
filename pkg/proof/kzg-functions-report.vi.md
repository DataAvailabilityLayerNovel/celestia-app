# Tong hop Ham Da Xay Dung Va Luong Da Kiem Thu KZG

Ngay cap nhat: 2026-04-12

## 1) Pham vi

Tai lieu nay tong hop trong mot file duy nhat:

- Cac ham da xay dung lien quan muc tieu KZG.
- Cac luong thuc thi da co kiem thu trong pkg/proof.

Luu y:

- Cac file KZG trong pkg/proof hien dang gate boi build tag kzgexperimental.
- Luong NMT cu van la luong mac dinh khi khong bat tag.

## 2) Ham da xay dung lien quan KZG

### 2.1 Generate proof va helper

File: pkg/proof/proof_generation_kzg.go

- NewShareInclusionProofFromEDSWithKZG
  - Tao proof huong KZG tu EDS + DAH + namespace.
  - Buoc chinh: lay range namespace, xac dinh cot, tao proof theo cot, dong goi output.
  - Trang thai: skeleton, chua production-ready.

- createKZGMultiProofForColumn
  - Khung quotient polynomial cho mot cot.
  - Trang thai: partial, phan commit proof point con placeholder.

- shareToByteSlice
  - Helper convert share sang [][]byte.
  - Trang thai: dung duoc.

- extractSharesForNamespace
  - Cat du lieu share theo range.
  - Trang thai: can chuan hoa tiep voi ODS/EDS mapping cuoi cung.

- squareSizeFromODS
  - Suy square size tu do dai ODS.
  - Trang thai: helper co ban.

- VerifyKZGMultiProofAgainstColumnCommitment
  - Khung verify proof cot.
  - Trang thai: placeholder.

### 2.2 Verify proof KZG

File: pkg/proof/proof_verification_kzg.go

- VerifyShareProofKZG
  - Khung verify tong the proof.
  - Trang thai: partial.

- verifyColumnPairing
  - Pairing check cap cot.
  - Trang thai: TODO placeholder.

- validateShareDataConsistency
  - Check hinh dang du lieu proof.
  - Trang thai: basic.

- VerifyCommitmentProofKZG
  - Khung verify commitment inclusion.
  - Trang thai: partial.

- verifyColumnInDataRoot
  - Membership check commitment len root.
  - Trang thai: TODO placeholder.

- CheckProofBoundaries, ValidateProofStructure, PolynomialCommitmentSize, ProofSize
  - Utility va structural checks.
  - Trang thai: basic.

- ReconstructInterpolationCommitment
  - Dung commitment noi suy tu shares.
  - Trang thai: partial, can review tiep theo API scalar.

### 2.3 Polynomial utilities

File: pkg/proof/proof_polynomial.go

- InterpolatePolynomial
- BuildVanishingPolynomial
- ComputeQuotientPolynomial
- ShareBytesToFieldElements
- FieldElementsToShareBytes
- ExtractCellsFromColumn
- ValidatePolynomialEvaluation
- evaluatePolynomial

Trang thai:

- Da co khung tinh toan.
- Chua dong bo day du cho production pipeline khi bat tag experimental.

### 2.4 Model va type KZG

File: pkg/proof/proof_kzg.go

- KZGMultiProof
- CommitmentProof
- NamespaceRange
- PairingVerificationInput
- NewKZGMultiProof
- NewCommitmentProof
- NewNamespaceRange

Trang thai:

- Model da co.
- Con can dong bo voi proto final khi chot wire format.

### 2.5 Primitive can dung tu cda

Module cda (dependency):

- cda.ComputeAndSetKateCommitments
  - Tinh PieceComm va ColumnComm, set vao EDS.

- cda.ComputeOpenProofCells
  - Sinh opening proof cho toan bo grid.

- codec.GenerateCoeffsByColHeight
  - Sinh coeff deterministic theo context dau vao.

- kzgProvider.Combine va kzgProvider.CombineProofs
  - Combine commitment/proof theo coeff RLNC.

- kzgProvider.Verify
  - Chay pairing verify cho opening proof.

Ghi chu:

- Neu module pin co ComputeOpenProofCell thi uu tien ham single-cell.
- Neu chua co thi fallback ComputeOpenProofCells + cat index cell.

## 3) Luong thuc thi da co kiem thu

File test: pkg/proof/proof_test.go

### 3.1 Commitment flow va proof object co the tao

- TestKateCommitmentsAndColumnProofs
  - Tao EDS.
  - Tinh va set commitments.
  - Tao DAH thanh cong.
  - KateCols khop ColumnComm.
  - Tao duoc Kate commitment proof cho mot cot.

### 3.2 Guard khi chua set commitment

- TestKateRootRequiresCommitments
  - Chua goi ComputeAndSetKateCommitments.
  - KateRoot va NewDataAvailabilityHeader phai tra loi.

### 3.3 ColumnComm combine dung tu PieceComm + coeff deterministic

- TestColumnCommitmentDeterministicCombine
  - Lay piece theo cot: PieceComm[col*k : (col+1)*k].
  - coeff = GenerateCoeffsByColHeight(col, n).
  - provider.Combine(...) phai bang ColumnComm[col].

### 3.4 Luong pairing verify theo tung cell

- TestPerCellPairingVerificationFlow
  - Lay open proofs cua cell (row,col) tu tap open proof.
  - CombineProofs theo cung coeff deterministic cua cot.
  - Lay claimed value tu combined proof.
  - Verify(ColumnComm[col], row, claimedValue, combinedProof) phai true.

## 4) Ket luan hien trang

- Da co primitive va test cho commitment flow va pairing execution flow cap cell.
- Da co test xac minh ColumnComm la ket qua combine PieceComm theo coeff deterministic.
- Phan verify tong the trong pkg/proof/proof_verification_kzg.go van la khung va con TODO cho cac ham placeholder.

## 5) Huong tiep theo

1. Chot wire format proof range-level.
2. Noi verify 2 pha vao implementation production:
   - Pha commitment inclusion.
   - Pha per-cell opening verify.
3. Chuyen cac ham TODO placeholder sang pairing check that su.
