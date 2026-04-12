# KZG Range Proof Spec (Huong 1)

Ngay cap nhat: 2026-04-09

## 1) Muc tieu

Xay dung 1 proof object duy nhat cho toan bo range `[startCell, endCell)` cua 1 namespace, de verifier co the:

- Xac nhan cot lien quan nam trong Kate root cua header.
- Xac nhan tung cell/share trong range mo ra dung voi commitment cot tuong ung.

Nguyen tac bat buoc:

- Khong viet lai thuat toan commitment/proof.
- Su dung cac primitive trong `cda` va EDS API de dam bao khop `ColumnComm` trong header.

## 2) Cac primitive bat buoc tu cda/EDS

1. Tinh commitment cot:

- `cda.ComputeAndSetKateCommitments(codec, eds, kzg)`
- ket qua duoc set vao `eds.KatePieceCommitments()` va `eds.KateCols()`.

2. Proof inclusion commitment cot len root:

- `eds.BuildKateCommitmentProof(col)`
- `eds.KateRoot()` hoac root tu header (`dah.Hash()`).

3. Open proof cho cell:

- Uu tien: `ComputeOpenProofCell(codec, eds, kzg, row, col)` neu co san trong version module.
- Fallback (module hien tai): `ComputeOpenProofCells(codec, eds, kzg)` roi lay dung index cell.

4. He so RLNC theo cot:

- `codec.GenerateCoeffsByColHeight(col, n)`.

## 3) Dinh dang proof object (de xuat)

```text
KZGRangeProof {
  namespace_id: bytes
  namespace_version: uint32

  start_cell: uint32
  end_cell: uint32              // end-exclusive

  data_root: bytes              // = dah.Hash()
  width: uint32                 // EDS width = n
  max_chunks: uint32            // RLNC k

  columns: []ColumnWitness
  cells: []CellWitness
}

ColumnWitness {
  col: uint32
  column_commitment: bytes      // ColumnComm[col]
  commitment_proof: KateMerkleProofBytes
}

CellWitness {
  row: uint32
  col: uint32
  share_data: bytes             // full cell bytes

  // k opening proofs cua cell (ung voi k piece trong cell)
  piece_open_proofs: []bytes    // len = k
}
```

Ghi chu:

- `columns` chi chua cot bi anh huong trong range.
- `cells` chua du lieu cell thuc te + opening proof cho chinh cell do.
- Khong can dua toan bo `PieceComm`; verifier chi can `ColumnComm[col]` va commitment proof len root.

## 4) Thuat toan generate (prover)

Input:

- `eds`, `dah`, `namespace`, `startCell`, `endCell`, `codec`, `kzg`.

Tien dieu kien:

- `ComputeAndSetKateCommitments` da duoc goi tren dung `eds` dung de tao `dah`.
- `namespace` map dung vao range trong `dah.NamespaceIndex`.

Buoc:

1. Xac dinh danh sach cell va tap cot bi anh huong.

- map index tuyến tinh sang `(row, col)` voi:
  - `row = idx / squareSizeODS`
  - `col = idx % squareSizeODS`

2. Tao bang chung commitment cho tung cot bi anh huong.

- Lay `column_commitment = dah.ColumnComm[col]`.
- Tao `commitment_proof = eds.BuildKateCommitmentProof(col)`.
- Them vao `columns`.

3. Tao bang chung open proof cho tung cell trong range.

- Neu co API single-cell:
  - `piece_open_proofs = ComputeOpenProofCell(codec, eds, kzg, row, col)`.
- Neu khong:
  - goi `ComputeOpenProofCells(codec, eds, kzg)` 1 lan,
  - cat proof theo index `((row*n)+col)*k ... +k`.
- Lay `share_data` tu ODS/EDS theo chi so cell va them vao `cells`.

4. Dong goi proof object.

- Gan `data_root = dah.Hash()`.
- Gan thong tin namespace + range + width + k.

## 5) Thuat toan verify (verifier)

Input:

- `proof`, `dah`, `codec`, `kzg`.

Pha A: Verify commitment cot len root

1. Kiem tra `proof.data_root == dah.Hash()`.
2. Kiem tra `start_cell < end_cell`, namespace hop le.
3. Duyet `columns`:

- verify `commitment_proof` voi root (`dah.Hash()` hoac `eds.KateRoot()` tuy API verify).
- doi chieu `column_commitment` trong proof voi `dah.ColumnComm[col]`.

Pha B: Verify tung cell/share 4. Cho moi `CellWitness{row,col,share_data,piece_open_proofs}`:

- Kiem tra `col` thuoc tap cot da duoc chung minh o Pha A.
- Tach `share_data` thanh `k` piece (piece-size = `len(share_data)/k`).
- Tinh `coeffs = codec.GenerateCoeffsByColHeight(col, n)`.
- Combine opening proofs:
  - `combined_proof = kzg.CombineProofs(piece_open_proofs, coeffs)`.
- Combine piece values theo cung `coeffs` de ra `combined_value`.
- Verify KZG opening tai `row` voi commitment cot:
  - `kzg.Verify(column_commitment, row, combined_value, combined_proof)`.

5. Neu tat ca cell pass -> proof hop le.

## 6) Chi tiet quan trong de khop header

- Header hash hien tinh tren `ColumnComm`.
- Vi vay, moi verify cell bat buoc quy ve commitment cot `ColumnComm[col]`.
- Khong dung commitment tu he thong tinh toan khac (tranh mismatch root).

## 7) Do phuc tap

Goi:

- `m = endCell - startCell` (so cell trong range)
- `c = so cot bi anh huong` (`c <= m`)
- `k = max chunks`

Chi phi xap xi:

- Commitment-inclusion verify: `O(c * log n)`
- Cell opening verify: `O(m * k)` cho combine + verify

Neu dung `ComputeOpenProofCell`:

- Prover chi tinh proof can thiet cho `m` cell.

Neu dung `ComputeOpenProofCells`:

- Prover co the ton `O(n*n*k)` de precompute roi cat.

## 8) Tinh trang implementation hien tai

- Primitive commitments/coefficient/open-proof da co trong cda.
- Layer proof package can:
  - chuan hoa object proof cho range-level,
  - dong bo proto/model voi semantics KZG,
  - noi verify 2 pha theo spec nay.

## 9) Open questions can chot truoc khi code

1. Canonical encoding cho `KateMerkleProof` trong wire format la gi?
2. `ComputeOpenProofCell` co san trong branch/module pin hien tai hay can fallback?
3. `combined_value` format dua vao `kzg.Verify` se dung bytes encoding nao (field element packing)?
4. Range mapping su dung ODS linear index hay EDS linear index can chot 1 chuan duy nhat.
