# KZG-first App Execution Plan (de core trien khai)

Muc tieu: hoan thien deliverables ben celestia-app de core co the cap nhat KZG-first voi ro rang ve tuong thich va interop.

## Hien trang (doi chieu checklist)

- Da chot commit hash proto va xac nhan schema/contract toi thieu.
- Da co mo ta version matrix va migration policy.
- Chua co descriptor set, golden vectors, huong dan chay interop.
- RPC/JSON contract chua o trong scope.

## Phase A - Hoan thien artifacts con thieu

1. Tao descriptor set (neu can cho grpcurl/protoc decode).

Deliverable:

- Descriptor set duoc commit (neu can).

## Phase B - Interop artifacts

1. Tao bo golden vectors (binary payload):
   - ShareProof hop le
   - ShareProof loi: empty proofs
   - ShareProof loi: mismatched column_proofs/column_indices
   - ShareProof loi: root_commitment mismatch
   - DAH hop le voi fields moi
2. Mo ta expected results (pass/fail + ly do) cho tung vector.

Deliverable:

- Thu muc testdata + tai lieu expected results.

## Phase C - Gate/flag neu can dual-mode

1. Neu can dual-mode, dinh nghia gate/flag va thoi diem remove legacy.

Deliverable:

- Gate/flag duoc mo ta ro rang (md).

## Phase D - Huong dan thuc thi

1. Viet huong dan chay interop (lenh, input/output) de core tai su dung.

Deliverable:

- Playbook interop (md).

## Tieu chi hoan thanh

- Core co du: proto on dinh + golden vectors + gate/flag (neu can) + huong dan chay interop.
- Core co the tiep tuc Phase 1 (proto regen) ma khong con phu thuoc thong tin thieu.
