# Tong hop Ham Da Xay Dung Va Luong Da Kiem Thu KZG

Ngay cap nhat: 2026-04-12

## 1) Pham vi

Tai lieu nay tong hop trong mot file duy nhat:

- Cac ham lien quan muc tieu KZG da duoc trien khai va da duoc test.
- Cac khung KZG cu trong nhom kzgexperimental va trang thai con ton dong.

Luu y:

- Luong mac dinh khong bat tag van la luong NMT legacy.
- Nhom file KZG experimental van gate boi build tag kzgexperimental.

## 2) Ham da trien khai production-safe cho range-level

File: pkg/proof/kzg_range_proof.go

### 2.1 Wire format range-level

- KZGRangeProof
  - NamespaceID, NamespaceVersion.
  - StartCell, EndCell (end-exclusive).
  - DataRoot, Width, MaxChunks.
  - ColumnProofs, CellProofs.

- KZGColumnProof
  - Column.
  - Commitment.
  - Proof (Merkle proof tu header ColumnComm).

- KZGCellProof
  - Row, Column.
  - ShareData.
  - PieceOpenProofs (k opening proofs cua cell).

Trang thai:

- Da trien khai va da su dung trong test end-to-end.

### 2.2 Tao range proof tu EDS + DAH

- NewKZGRangeProofFromEDS
  - Input: EDS, DAH, namespace, codec, provider.
  - Buoc 1: Lay namespace range tu DAH.NamespaceRange.
  - Buoc 2: Xac dinh cot bi anh huong tu range share.
  - Buoc 3: Tao commitment inclusion proof theo cot tu dah.ColumnComm bang merkle.ProofsFromByteSlices.
  - Buoc 4: Tao opening proof grid bang cda.ComputeOpenProofCells va cat theo (row,col).
  - Buoc 5: Dong goi ve KZGRangeProof.

Trang thai:

- Da trien khai day du va duoc dung trong test build+verify.

### 2.3 Verify 2 pha trong implementation

- VerifyKZGRangeProof
  - Pha 1: commitment inclusion.
    - Check DataRoot khop dah.Hash().
    - Check commitment proof cot khop dah.ColumnComm.
    - Verify Proof.Verify(root, commitment).
  - Pha 2: per-cell opening verify.
    - Check cell chi tham chieu cot da verify.
    - CombineProofs theo coeff deterministic GenerateCoeffsByColHeight.
    - Doc claimed value tu combined opening proof.
    - Pairing verify bang provider.Verify.

Trang thai:

- Da trien khai day du, khong con placeholder trong flow moi nay.

### 2.4 Helper

- clone2D
  - Deep-copy [][]byte cho proof aunts/du lieu nested.

Trang thai:

- Da dung trong flow tao proof.

## 3) Primitive da duoc su dung trong flow moi

Tu dependency cda va codec:

- cda.ComputeAndSetKateCommitments
  - Tinh PieceComm va ColumnComm, set vao EDS.

- cda.ComputeOpenProofCells
  - Tao opening proofs cho toan bo grid.

- codec.GenerateCoeffsByColHeight
  - Sinh coeff deterministic theo (column, width).

- provider.Combine / provider.CombineProofs
  - Combine commitments/proofs theo coeff RLNC.

- provider.Verify
  - Pairing verify opening proof theo cot.

## 4) Luong thuc thi da co kiem thu

File test: pkg/proof/proof_test.go

### 4.1 Commitment flow va guard

- TestKateCommitmentsAndColumnProofs
  - Tao EDS, set commitments, tao DAH.
  - KateCols khop ColumnComm.
  - Tao duoc commitment proof cho cot.

- TestKateRootRequiresCommitments
  - Neu chua set commitments thi KateRoot/NewDataAvailabilityHeader tra loi.

### 4.2 Deterministic combine

- TestColumnCommitmentDeterministicCombine
  - Verify ColumnComm[col] = Combine(PieceComm[col*k:(col+1)*k], coeffs).

### 4.3 Per-cell pairing flow

- TestPerCellPairingVerificationFlow
  - Lay open proofs cua mot cell.
  - CombineProofs theo coeff cot.
  - Rut claimed value tu combined proof.
  - provider.Verify phai true.

### 4.4 Range-level end-to-end va tamper case

- TestBuildAndVerifyKZGRangeProof
  - Build KZGRangeProof tu EDS+DAH+namespace.
  - VerifyKZGRangeProof pass.

- TestVerifyKZGRangeProofRejectsTamperedColumnCommitment
  - Tamper commitment trong ColumnProofs.
  - VerifyKZGRangeProof phai fail.

## 5) Ket luan hien trang

- Muc tieu trong plan da duoc thuc hien tren flow moi:
  - Da chot wire format range-level.
  - Da noi verify 2 pha vao implementation.
  - Da chay pairing check that su trong verify path moi.
- Package test cua pkg/proof dang pass o default flow.

## 6) Ton dong va buoc tiep theo

### 6.1 Nhom kzgexperimental cu

- Cac file nhu proof_generation_kzg.go, proof_verification_kzg.go, proof_polynomial.go van con partial/TODO va hien khong pass khi bat -tags=kzgexperimental.

### 6.2 Dong bo schema va generated code

- Con viec dong bo proto/generated code de dua ShareProof wire model sang KZG-native nhat quan.

### 6.3 Tich hop API

- Can quyet dinh lo trinh thay the dan caller tu legacy flow sang KZGRangeProof (hoac bo sung adapter giu backward compatibility).
