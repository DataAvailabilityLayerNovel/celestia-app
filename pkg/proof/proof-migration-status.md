# Proof Migration Status (Kate Commitment + Cell Open Proof)

Ngay cap nhat: 2026-04-08

## Hoan thanh

- Chuyen luong proof sang mo hinh moi trong `pkg/proof/proof.go`:
  - `Proof` dung de chung minh commitment thuoc dung cot (Kate merkle proof).
  - `NMTProof` dung de chua open proofs cua cell trong range.

- Chuyen verify sang 2 pha trong `pkg/proof/share_proof.go`:
  - Pha 1: verify commitment proof len Kate root.
  - Pha 2: combine cell open proofs theo coeff RLNC va verify KZG cho gia tri cell.

- Cap nhat schema proto:
  - `NMTProof.leaf_hash` da duoc thay bang `NMTProof.cell_open_proofs` (repeated bytes) tai `proto/celestia/core/v1/proof/proof.proto`.
  - Dong bo generated code tai `pkg/proof/proof.pb.go`.

- Them API proof theo tung cell:
  - `NewCellInclusionProofs`
  - `NewCellInclusionProofsFromEDS`

- Cap nhat test theo luong moi:
  - `pkg/proof/proof_test.go`
  - `pkg/proof/share_proof_test.go`

- Da xoa phan row proof cu:
  - `pkg/proof/row_proof.go`
  - `pkg/proof/row_proof_test.go`

## Quan he giua cell va share

- Trong implementation hien tai cua package proof, 1 share trong range can prove duoc map truc tiep thanh 1 cell trong EDS tai vi tri `(row, col)`.
- Nghia la trong context nay: share ~= cell duoc verify.
- Du lieu thuc te can verify la bytes cua cell do (duoc luu trong `ShareProof.Data`).
- Moi cell thuoc 1 cot `col`, va cot do co 1 commitment KZG:
  - `Proof` chung minh commitment nay nam trong Kate root va dung voi cot `col`.
  - `NMTProof.cell_open_proofs` chung minh du lieu cell o hang `row` mo ra dung voi commitment cot do.
- Tom lai theo luong verify:
  - share/cell -> thuoc cot nao?
  - commitment cot do co nam trong Kate root khong?
  - open proof cua chinh cell do co khop commitment cot khong?

## Cach tinh proof (da implement)

1. Tinh commitments theo cot

- Tao RLNC codec + KZG provider.
- Goi `cda.ComputeAndSetKateCommitments(codec, eds, kzg)`.
- Lay commitments bang `eds.KateCols()`.

2. Tinh root de verify commitment proof

- Tao DAH va lay `dah.Hash()` lam Kate root su dung khi verify.

3. Tinh proof commitment cho cot i

- Goi `eds.BuildKateCommitmentProof(uint(i))`.
- Dong goi vao `Proof`:
  - `Total = NumLeaves`
  - `Index = ProofIndex`
  - `LeafHash = commitment cot i`
  - `Aunts = ProofSet`

4. Tinh proof du lieu cho cell [i,j]

- Tao toan bo open proofs bang `cda.ComputeOpenProofCells(codec, eds, kzg)`.
- Lay dung nhom proofs cua cell theo chi so `(row, col)`.
- Luu vao `NMTProof.cell_open_proofs`.

5. Verify

- Verify commitment proof len root (pha 1).
- Combine open proofs theo coeff RLNC cua cot.
- Combine gia tri cac manh trong cell theo cung coeff.
- Verify KZG o vi tri row (pha 2).

## Trang thai hien tai

- `go test ./pkg/proof -count=1` da PASS.

## Viec tiep theo

- Chay gate lon hon neu can:
  - `make build`
  - `make test-short`
- Can nhac bo doi ten `NMTProof` trong proto o buoc tiep theo de phan anh dung semantics moi (khong con NMT leaf proof).
