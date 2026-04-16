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

## Muc dang trien khai: gop 2 tang proof (cell -> row -> final)

Y tuong da chot:

1. Tang 1 (trong moi row)

- Voi moi cell `(row, col)` trong range:
  - Dung `GenerateCoeffsByColSeed(col, d)` de combine piece proofs cua cell thanh 1 cell proof.
- Voi moi row co nhieu cell:
  - Sinh vector `g_row` (Fiat-Shamir hoac deterministic theo transcript).
  - Combine cac cell proofs trong row bang `provider.CombineProofs` -> `row_proof`.
  - Combine cac column commitments tuong ung bang `provider.Combine` -> `row_commit`.

2. Tang 2 (gop cac row)

- Muc tieu la tao 1 final proof duy nhat tu danh sach `(row_proof_i, row_commit_i)`.
- Luu y quan trong:
  - KHONG duoc dung truc tiep `CombineProofs(row_proof_i, ...)` de verify nhu mot opening proof thong thuong,
    vi moi `row_proof_i` mo tai diem khac nhau (chi so row khac nhau).
  - `CombineProofs` chi dung an toan khi cac proof mo cung mot diem.
- Cach dung de an toan:
  - Batched verification tren cap row bang random challenge `rho` (Fiat-Shamir).
  - Verifier check mot phuong trinh pairing tong hop (multi-pairing) cho tat ca rows,
    thay vi ep ve 1 opening proof tai 1 diem.

Noi ngan gon:

- Co the gop logic verify cua nhieu row ve 1 lan verify cuoi,
  NHUNG khong phai bang cach doi row proofs thanh 1 opening proof thong thuong.

## Ke hoach implement cu the

1. M1 - Row-level aggregation

- [x] Them cau truc `KZGRowProof` (row, row_commit, row_proof, metadata cot/cell can thiet).
- [x] Builder tao row proofs tu cell proofs trong `kzg_range_proof.go`.
- [x] Verify row proof doc lap (moi row 1 check) de lam baseline dung.

2. M2 - Final batched verification across rows

- [x] Them transcript challenge `rho` (derive tu DataRoot + namespace + danh sach rows/commits).
- [x] Implement batch consistency verifier:
  - [x] Recombine row proofs/commits theo coeff transcript.
  - [x] Verify transcript + coeff + combined payload khop.
- [x] Dam bao deterministic transcript va reject neu ordering khong khop.
- [ ] Multi-pairing check 1 lan cho tat ca rows (can primitive API cap thap hon tu KZG backend).

3. M3 - Wiring API

- [x] `NewKZGRangeProofFromEDS` tra ve row-proof payload + metadata cho batch verify (`RowBatch`).
- [x] `VerifyKZGRangeProof`:
  - [x] Verify commitment-in-header (pha 1) nhu hien tai.
  - [x] Neu payload co nhieu rows: chay row-batch consistency verify.
  - [x] Verify tung row cryptographically sau batch consistency check.

4. M4 - Test

- [x] Golden test: proof range 1 row va nhieu row deu pass.
- [x] Negative test: sua 1 row_commit, 1 row_proof, hoac 1 cell data -> batch verify fail.
- [x] Determinism test cho transcript challenge.
- [ ] Benchmark:
  - [ ] verify tung row
  - [ ] verify batch all rows
  - [ ] so sanh chi phi.

## Tinh trang hien tai cua huong nay

- Da xac nhan codebase co san primitive can thiet:
  - `provider.Combine`
  - `provider.CombineProofs`
- Da implement M1 trong `kzg_range_proof.go`:
  - Build row proofs tu danh sach cell proofs.
  - Verify row proofs trong `VerifyKZGRangeProof` (uu tien path row-proof neu co payload).
  - Them test tamper row proof de dam bao fail-case.
- Da implement M2 muc transcript + recombine consistency trong `kzg_range_proof.go`:
  - Them `RowBatch` (transcript, coeffs, combined row proof/commitment).
  - Verifier recompute va doi chieu toan bo payload batch.
  - Them test tamper row batch de dam bao fail-case.
- Da them file test rieng cho row-batch flow:
  - `pkg/proof/kzg_range_proof_row_batch_test.go`
  - Gom nhom test golden, negative va deterministic.
- Gioi han hien tai:
  - Chua the verify "1 pairing check duy nhat" cho tat ca rows voi API `cda.KZGProvider` hien co.
  - Van verify cryptographically tung row sau khi pass batch consistency.
