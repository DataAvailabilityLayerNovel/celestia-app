# KZG-first App Deliverables Checklist

Muc dich: chot cac dau vao tu celestia-app can thiet de trien khai KZG-first trong celestia-core.

## 1. Proto va schema

- [x] Chot commit hash cua `proof.proto` va `data_availability_header.proto` (KZG-first). (c1ccf1b994dd0e3e3302cdb747e5ca53b499587e)
- [ ] Cung cap descriptor set (neu dung grpcurl/protoc decode). (chua commit; neu can se tao tu commit tren)
- [x] Xac nhan field numbers/ten khong doi giua cac mieu ta (proto <-> docs). (tham chieu docs/architecture/proto-kzg-interop-pack.md)

## 2. Wire contract va validation

- [x] Chot quy tac validate toi thieu cho `ShareProof` (share_proofs non-empty, commitment_proof bat buoc, len(column_proofs)==len(column_indices), root_commitment match neu co). (tham chieu docs/architecture/proto-kzg-interop-pack.md)
- [x] Chot quy tac doc deprecated fields trong DAH (chi doc tam thoi hay bo hoan toan). (tam thoi doc de tuong thich, uu tien fields moi)
- [ ] Neu co version gate, cung cap dieu kien/flag cu the. (chua co gate cu the trong repo)

## 3. Golden vectors (binary payload)

- [ ] `ShareProof` hop le (du data + proofs + commitment_proof). (can tao vector)
- [ ] `ShareProof` loi: empty proofs. (can tao vector)
- [ ] `ShareProof` loi: mismatched column_proofs/column_indices. (can tao vector)
- [ ] `ShareProof` loi: root_commitment mismatch. (can tao vector)
- [ ] `DataAvailabilityHeader` hop le voi fields moi (piece_commitments, column_commitments, namespace_index). (can tao vector)
- [x] Tai lieu hoa expected results cho tung vector (pass/fail + ly do). (tham chieu docs/architecture/proto-kzg-interop-pack.md)

## 4. Interop/version matrix

- [x] Dinh nghia ro cac cap version can test: new->new, new->old, old->new. (tham chieu docs/architecture/proto-kzg-interop-pack.md)
- [x] Neu can backward compatibility, chi ro han su dung va thoi diem remove legacy. (nêu dual-mode vs hard break trong docs)
- [ ] Cung cap huong dan chay interop tests (lenh, input/output). (chua co lenh cu the trong repo)

## 5. RPC/JSON contract (neu co)

- [ ] Chot payload schema cho prove_shares (hoac prove_shares_v3 neu versioned). (chua co RPC trong scope)
- [x] Ky vong error khi payload legacy duoc gui toi endpoint moi. (neu co wrapper JSON, phai tra loi ro cho proof thieu truong)
- [x] Mieu ta mapping bytes fields trong JSON (base64 quy uoc). (tham chieu docs/architecture/proto-kzg-interop-pack.md)

## 6. Release/migration note

- [x] Ghi ro migration policy (hard break vs dual-mode). (tham chieu docs/release-notes/kzg-proto-migration.md)
- [x] Ghi ro thong tin tuong thich va huong dan nang cap cho consumers. (tham chieu docs/release-notes/kzg-proto-migration.md)
