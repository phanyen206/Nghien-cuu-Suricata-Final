# Mô hình phát hiện Scan bằng Decision Tree

## 1. Mục tiêu

Xây dựng mô hình Decision Tree để phân loại các cửa sổ lưu lượng mạng thành hai lớp:

- `Scan`: các mẫu thuộc nhãn `scan` hoặc `scan_small`.
- `Benign`: lưu lượng bình thường và các nhãn không thuộc lớp Scan trong phạm vi bài toán.

Mô hình được đánh giá song song với kết quả cảnh báo của Suricata trên các lát dữ liệu thực nghiệm.

## 2. Cấu trúc thư mục

- `scripts/`: mã nguồn xử lý dữ liệu, huấn luyện, đánh giá và đối chiếu.
- `results/`: bảng kết quả định lượng và biểu đồ.
- `data/`: dữ liệu đặc trưng đầu vào dùng cho huấn luyện và đánh giá.

## 3. Môi trường

Python 3.10 trở lên. Cài đặt thư viện:

```bash
python -m pip install -r requirements.txt
```

Các thư viện chính: NumPy, pandas, Matplotlib, scikit-learn và dpkt.

## 4. Quy trình thực nghiệm

Quy trình đầy đủ từ PCAP:

1. Đặt PCAP Friday của CIC-IDS2017 theo đường dẫn được cấu hình trong `cut.py`.
2. Chạy `cut.py` để cắt các khoảng thời gian thành các lát PCAP.
3. Chạy `11_extract_features.py` để trích xuất đặc trưng theo cửa sổ 10 giây.
4. Chạy `ban_hoan_chinh.py` để huấn luyện bốn bộ đặc trưng, đánh giá và xuất bảng/biểu đồ.
5. Chạy `14_compare.py` để đối chiếu kết quả Decision Tree với các lần chạy Suricata.

Mặc định, các chương trình sử dụng thư mục `D:\\CIC-IDS2017`. Có thể đặt biến môi trường `CIC_DIR` để chỉ định thư mục dữ liệu khác.

Ví dụ PowerShell:

```powershell
$env:CIC_DIR = "D:\CIC-IDS2017"
python .\scripts\cut.py
python .\scripts\11_extract_features.py
python .\scripts\ban_hoan_chinh.py
python .\scripts\14_compare.py
```

Nếu đã có `features.csv`, có thể chạy trực tiếp `ban_hoan_chinh.py` và bỏ qua bước cắt PCAP/trích xuất đặc trưng.

## 5. Thiết lập mô hình

- Thuật toán: `DecisionTreeClassifier`.
- Độ sâu tối đa: `max_depth=3`.
- Xử lý mất cân bằng lớp: `class_weight="balanced"`.
- Hạt giống ngẫu nhiên: `random_state=42`.
- Cửa sổ trích xuất đặc trưng: 10 giây.

Bốn bộ đặc trưng được so sánh:

1. `HANH_VI`
2. `HANH_VI+WINDOW`
3. `KHONG_KHOI_LUONG`
4. `CHI_WINDOW`

Tập huấn luyện gồm `scan_A` và `benign_train`. Tập kiểm tra gồm `scan_B`, `scan_C` và `benign_test`. Các lát `scan_U`, `scan_small` và `ddos` được dùng để đánh giá mở rộng theo cách gán nhãn được định nghĩa trong mã nguồn.

## 6. Kết quả

- [Bảng đánh giá mô hình](results/dt_summary.csv)
- [Bảng đối chiếu với Suricata](results/bang_so_sanh.csv)
- Biểu đồ: ma trận nhầm lẫn, so sánh Precision/Recall/F1, mức độ quan trọng đặc trưng và diễn biến phát hiện theo thời gian.

Các chỉ số trong bảng là kết quả thực nghiệm được lưu kèm repository. Không diễn giải khả năng phân loại Scan/Benign thành khả năng phát hiện mọi loại tấn công: riêng nhãn DDoS được xem là lớp 0 trong bài toán phân loại Scan/Benign và được phân tích riêng khi đối chiếu với Suricata.

## 7. Lưu ý tái lập

Các tệp PCAP gốc của CIC-IDS2017 không được lưu trong repository. Người thực hiện cần có bộ dữ liệu PCAP hợp lệ và đặt đúng đường dẫn trước khi chạy toàn bộ quy trình. Nếu chỉ có `features.csv`, có thể chạy bước huấn luyện/đánh giá mà không cần cắt và trích xuất PCAP lại.

Kết quả phụ thuộc vào dữ liệu đầu vào và phiên bản thư viện. Không thay thế PCAP, log hoặc dữ liệu thực nghiệm bằng dữ liệu tự tạo khi báo cáo kết quả.
