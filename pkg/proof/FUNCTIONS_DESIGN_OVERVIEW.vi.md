# pkg/proof: Chức năng và thiết kế chính

Tài liệu này tóm tắt nhanh các chức năng cốt lõi trong `pkg/proof`, cách các thành phần phối hợp với nhau, và các điểm kiểm tra tính đúng đắn của proof.

## 1) Mục tiêu của package

`pkg/proof` cung cấp cơ chế tạo và kiểm tra proof để chứng minh:

- một transaction cụ thể đã được đưa vào data root của block;
- một dải share (cùng namespace) đã được đưa vào data root của block.

Proof được xây từ hai lớp:

- NMT proof: share -> row root;
- Binary Merkle proof: row root -> data root.

## 2) Thành phần theo file

### `proof.go`

Chứa logic tạo proof chính.

- `NewTxInclusionProof(txs, txIndex, _)`
  - Tạo proof cho transaction tại `txIndex`.
  - Dùng `square.NewBuilder(...)` để dựng data square từ danh sách tx.
  - Tìm range share của tx bằng `FindTxShareRange`.
  - Xác định namespace tx (`TxNamespace` hoặc `PayForBlobNamespace`) qua `getTxNamespace`.
  - Gọi `NewShareInclusionProof(...)` để dựng proof cuối.

- `getTxNamespace(tx)`
  - Phân biệt blob tx hay tx thường để chọn namespace phù hợp.

- `NewShareInclusionProof(dataSquare, namespace, shareRange)`
  - Extend ODS thành EDS bằng `da.ExtendShares(...)`.
  - Chuyển sang `NewShareInclusionProofFromEDS(...)`.

- `NewShareInclusionProofFromEDS(eds, namespace, shareRange)`
  - Tính row chứa dải share.
  - Lấy `RowRoots` và `ColRoots` từ EDS.
  - Tạo Merkle proofs cho row roots tới data root.
  - Thu thập các row liên quan, rồi tạo NMT proofs share -> row root.
  - Trả về `ShareProof` hoàn chỉnh.

- `CreateShareToRowRootProofs(...)`
  - Với mỗi row liên quan:
    - dựng lại erasured NMT;
    - push toàn bộ share của row vào cây;
    - kiểm tra root cây vừa dựng phải khớp row root trong EDS;
    - tạo proof cho đoạn leaf cần chứng minh.
  - Trả về danh sách `NMTProof` và dữ liệu raw shares.

- `safeConvertUint64ToInt(...)`
  - Chặn overflow khi ép kiểu.

### `share_proof.go`

Chứa logic validate/verify cho `ShareProof`.

- `ShareProof.Validate(root)`
  - Kiểm tra dữ liệu proof không rỗng.
  - Kiểm tra số lượng `ShareProofs` khớp số `RowRoots`.
  - Kiểm tra tổng số share trong proofs khớp `Data`.
  - Kiểm tra chỉ số `Start/End` của từng proof hợp lệ.
  - Gọi `RowProof.Validate(root)`.
  - Gọi `ShareProof.VerifyProof()`.

- `ShareProof.VerifyProof()`
  - Duyệt từng `NMTProof`, dựng inclusion proof và verify lên row root tương ứng.
  - Sử dụng namespace `(version + id)` từ `NamespaceVersion` và `NamespaceId`.

### `row_proof.go`

Chứa logic validate/verify cho `RowProof` và wrapper cho Merkle proof.

- `RowProof.Validate(root)`
  - Kiểm tra số row, số `RowRoots`, số `Proofs` nhất quán.
  - Verify tất cả proof lên `root`.

- `RowProof.VerifyProof(root)`
  - Verify từng `Proof` (CometBFT merkle proof).

- `(*Proof).Verify(rootHash, leaf)`
  - Chuyển sang `merkle.Proof` của CometBFT để verify.

### `querier.go`

Cung cấp entrypoint query ABCI để tạo proof từ dữ liệu block.

- Hằng số path:
  - `TxInclusionQueryPath = "txInclusionProof"`
  - `ShareInclusionQueryPath = "shareInclusionProof"`

- `QueryTxInclusionProof(ctx, path, req)`
  - Parse `txIndex` từ path.
  - Unmarshal block từ `req.Data`.
  - Tạo tx inclusion proof.
  - Marshal proof trả về bytes.

- `QueryShareInclusionProof(ctx, path, req)`
  - Parse range `[beginShare, endShare)` từ path.
  - Unmarshal block từ `req.Data`.
  - Dựng data square bằng `square.Construct(...)`.
  - Xác thực namespace của range bằng `ParseNamespace(...)`.
  - Tạo share inclusion proof và marshal trả về bytes.

- `ParseNamespace(rawShares, startShare, endShare)`
  - Validate range:
    - start/end không âm;
    - end > start;
    - end không vượt số share.
  - Đảm bảo mọi share trong range cùng namespace.

- `safeConvertInt64ToInt(...)`
  - Chặn overflow/underflow khi ép kiểu.

### `proof.pb.go` (generated)

Định nghĩa message và codec Protobuf cho proof:

- `ShareProof`
  - `Data`: danh sách raw shares được chứng minh.
  - `ShareProofs`: các `NMTProof` theo row.
  - `NamespaceId`, `NamespaceVersion`.
  - `RowProof`: proof từ row roots tới data root.

- `RowProof`
  - `RowRoots`, `Proofs`, `StartRow`, `EndRow`.

- `NMTProof`
  - `Start`, `End`, `Nodes`, `LeafHash`.

- `Proof`
  - `Total`, `Index`, `LeafHash`, `Aunts`.

## 3) Thiết kế tổng thể (kiến trúc xử lý)

### Luồng A: Proof cho transaction

1. Nhận list tx và `txIndex`.
2. Dựng data square.
3. Xác định share range của tx.
4. Xác định namespace của tx.
5. Tạo `ShareProof` (NMT proofs + row proofs).
6. Trả proof dạng protobuf bytes nếu đi qua query path.

### Luồng B: Proof cho dải share

1. Nhận range `[start, end)` từ query path.
2. Dựng data square từ block data.
3. Kiểm tra range hợp lệ và cùng namespace (`ParseNamespace`).
4. Extend square -> EDS.
5. Tạo proofs:
   - share -> row root (NMT);
   - row root -> data root (binary merkle).
6. Trả `ShareProof`.

### Luồng C: Verify proof ở phía consumer

1. Gọi `ShareProof.Validate(dataRoot)`.
2. `Validate` kiểm tra cấu trúc, số lượng phần tử và range.
3. `RowProof.Validate` xác nhận row roots nằm dưới data root.
4. `ShareProof.VerifyProof` xác nhận shares nằm dưới row roots đúng namespace.

## 4) Các nguyên tắc an toàn/tính đúng đắn

- Kiểm tra biên chỉ số đầy đủ (âm, vượt range, end <= start).
- Dùng hàm ép kiểu an toàn để tránh overflow.
- Trước khi tạo NMT proof, tự dựng lại cây và bắt buộc root phải khớp row root EDS.
- Validate số lượng phần tử giữa các lớp proof để tránh proof không nhất quán.
- Test có case âm cho query index nhằm tránh lỗi xử lý giá trị âm.

## 5) Bao phủ test hiện có

- `proof_test.go`
  - Test tạo tx inclusion proof với nhiều vị trí tx và out-of-bounds.
  - Test tạo share inclusion proof với nhiều range hợp lệ/không hợp lệ.
  - Test prove toàn bộ shares cùng namespace.
  - Test query tx inclusion từ chối index âm.

- `row_proof_test.go`
  - Test `RowProof.Validate` cho trường hợp hợp lệ và các trường hợp sai cấu trúc.

- `share_proof_test.go`
  - Test `ShareProof.Validate` cho trường hợp hợp lệ và các trường hợp mismatch.

## 6) Ghi chú phạm vi

- `proof.pb.go` là file generated, không chỉnh tay.
- `pkg/proof/README.md` đang mô tả sâu về nền tảng Merkle/NMT và trực quan bằng hình ảnh.
- File này tập trung vào góc nhìn code-level: chức năng và thiết kế thực thi trong package.
