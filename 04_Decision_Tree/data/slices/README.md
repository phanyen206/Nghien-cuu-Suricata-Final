# PCAP đã cắt – Slices

## 1. Giới thiệu

Thư mục `slices` dùng để lưu trữ các tệp PCAP được cắt từ bộ dữ liệu CIC-IDS2017, phục vụ quá trình phân tích lưu lượng mạng và trích xuất đặc trưng cho mô hình Decision Tree.

Các tệp PCAP được sử dụng làm dữ liệu đầu vào cho quá trình xử lý và thực nghiệm.

## 2. Nguồn dữ liệu

- Bộ dữ liệu gốc: CIC-IDS2017.
- Định dạng: PCAP.
- Dữ liệu: các khoảng lưu lượng mạng được lựa chọn và cắt từ PCAP gốc để phục vụ thực nghiệm.
- Các tệp được phân chia theo từng nhóm lưu lượng và mục đích đánh giá mô hình.

## 3. Các tệp dữ liệu

Các tệp PCAP đã cắt được cung cấp trong gói mã nguồn Decision Tree nộp kèm trên Google Drive do giới hạn dung lượng lưu trữ của GitHub.

Khi sử dụng, giữ nguyên tên tệp và đặt các PCAP vào thư mục `slices` theo cấu trúc mà chương trình yêu cầu.

## 4. Cách sử dụng

1. Tải các tệp PCAP đã cắt từ gói dữ liệu thực nghiệm.
2. Giải nén và đặt các tệp vào thư mục `slices`.
3. Kiểm tra đường dẫn dữ liệu trong các script trước khi chạy.
4. Thực hiện trích xuất đặc trưng bằng chương trình `11_extract_features.py`.

## 5. Lưu ý

- Không thay đổi tên tệp PCAP nếu chưa cập nhật đường dẫn tương ứng trong mã nguồn.
- Không thay đổi nội dung PCAP trong quá trình thực nghiệm.
- Bộ PCAP gốc CIC-IDS2017 không được lưu trong thư mục này.
