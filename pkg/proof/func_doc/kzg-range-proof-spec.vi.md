# KZG Range Proof Spec (Implementation Hien Tai)

Ngay cap nhat: 2026-04-16

## 1) Muc tieu

Trong implementation hien tai, object proof cho 1 namespace range can bao dam:

- Chung minh cac column commitments lien quan nam trong header root.
- Chung minh du lieu cell/share trong range hop le theo KZG opening.
- Ho tro 2 cap gom proof:
  - cap row (`RowProofs`)
  - cap row-batch consistency (`RowBatch`)

## 2) Primitive dang dung

Tu `cda` va codec:

- `cda.ComputeAndSetKateCommitments(codec, eds, provider, seed)`
- `cda.ComputeOpenProofCells(codec, eds, provider)`
- `codec.GenerateCoeffsByColSeed(col, seed)`
- `provider.Combine(commits, coeffs)`
- `provider.CombineProofs(proofs, coeffs)`
- `provider.Verify(commit, row, value, proof)`

## 3) Wire format hien tai

```text
KZGRangeProof {
  namespace_id: bytes
  namespace_version: uint32

  start_cell: uint32
  end_cell: uint32

  data_root: bytes
  width: uint32
  max_chunks: uint32
  seed: int

  column_proofs: []KZGColumnProof
  cell_proofs: []KZGCellProof
  row_proofs: []KZGRowProof
  row_batch: *KZGRowBatch
}

KZGColumnProof {
  column: uint32
  commitment: bytes
  proof: Proof   // Merkle proof len root cua dah.ColumnComm
}

KZGCellProof {
  row: uint32
  column: uint32
  share_data: bytes
  piece_open_proofs: []bytes   // len = k
}

KZGRowProof {
  row: uint32
  columns: []uint32
  coeffs: []byte
  cell_combined_proofs: []bytes
  combined_proof: bytes
  combined_commitment: bytes
}

KZGRowBatch {
  transcript: bytes
  coeffs: []byte
  combined_proof: bytes
  combined_commitment: bytes
}
```

## 4) Generate algorithm

Input:

- `eds`, `dah`, `namespace`, `codec`, `provider`, `seed`

Buoc:

1. Lay namespace range tu `dah.NamespaceRange(namespace.Bytes())`.
2. Build `ColumnProofs` tren `dah.ColumnComm` bang `merkle.ProofsFromByteSlices`.
3. Build `CellProofs`:
   - goi `cda.ComputeOpenProofCells` 1 lan
   - cat dung proof segment theo `(row, col)`
4. Build `RowProofs`:
   - gom cells theo row
   - voi moi cell: combine piece proofs theo `GenerateCoeffsByColSeed`
   - voi moi row: combine lai proofs/commitments thanh `combined_proof` va `combined_commitment`
5. Build `RowBatch`:
   - derive transcript deterministic tu `(DataRoot, Namespace, RowProofs)`
   - derive batch coeffs tu transcript
   - combine tat ca row proofs/row commitments thanh payload batch

## 5) Verify algorithm

Input:

- `proof`, `dah`, `codec`, `provider`

Pha A - commitment inclusion:

1. Check `proof.data_root == dah.Hash()`.
2. Verify tung `KZGColumnProof` va doi chieu commitment voi `dah.ColumnComm[col]`.

Pha B - row path (neu co `RowProofs`):

1. Neu co `RowBatch`:
   - recompute transcript va coeffs
   - recombine row proofs/row commitments
   - doi chieu voi payload `RowBatch`
2. Verify cryptographically tung `KZGRowProof`:
   - recombine per-row proof/commitment de check consistency
   - `provider.Verify` tren moi row

Pha B - fallback cell path (neu khong co `RowProofs`):

1. verify theo per-cell flow cu.

## 6) Luu y an toan

- `CombineProofs` an toan khi combine cac proof cung diem mo.
- Trong implementation hien tai:
  - combine trong cung row duoc verify cryptographically tren row do.
  - cap `RowBatch` dang la consistency payload + transcript challenge.
- Chua co true "single multi-pairing check" cho tat ca rows voi API public hien co cua `cda.KZGProvider`.

## 7) Do phuc tap (hien tai)

Ky hieu:

- `m`: so cell trong range
- `r`: so row bi anh huong
- `c`: so cot bi anh huong
- `k`: max chunks

Chi phi xap xi:

- Commitment inclusion: `O(c * log n)`
- Build per-cell combine: `O(m * k)`
- Verify row cryptographic: `O(r)` pairing checks
- Row-batch consistency: `O(r)` recombine

## 8) Trang thai implementation

- Da noi duong build/verify day du trong `pkg/proof/kzg_range_proof.go`.
- Da co test correctness/golden/negative/determinism cho row-batch flow.

## 9) Muc chua lam

- True multi-pairing batch verify across rows (1 pairing check duy nhat) can primitive API cap thap hon tu backend KZG.
