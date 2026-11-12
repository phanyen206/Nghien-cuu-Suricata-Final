# Nghiên cứu hệ thống phát hiện xâm nhập Suricata

## Giới thiệu
Đề tài tìm hiểu và thực nghiệm hệ thống phát hiện xâm nhập mạng Suricata. Nội dung tập trung vào kiến trúc, triển khai môi trường thử nghiệm, cấu hình phát hiện và đánh giá khả năng nhận diện các hành vi tấn công mạng.

## Nội dung repository

| Thư mục | Nội dung |
|---|---|
| [01_Tai_lieu_huong_dan](01_Tai_lieu_huong_dan/) | Hướng dẫn chuẩn bị máy ảo, thiết lập mạng và cài đặt Suricata |
| [02_Cau_hinh_Suricata](02_Cau_hinh_Suricata/) | Cấu hình, quy tắc và lệnh vận hành Suricata |
| [03_Kich_ban_thuc_nghiem](03_Kich_ban_thuc_nghiem/) | 13 kịch bản thực nghiệm theo nội dung báo cáo |
| [04_Decision_Tree](04_Decision_Tree/) | Mã nguồn, dữ liệu đặc trưng và kết quả mô hình Decision Tree |
| [05_Danh_gia](05_Danh_gia/) | Phương pháp và kết quả đánh giá |

## Môi trường thực nghiệm
- VMware Workstation
- Ubuntu cho máy Attacker và Victim
- Suricata 8.0.3
- Mạng thử nghiệm nội bộ 192.168.100.0/24

Thông số giao diện mạng, phiên bản phần mềm và lệnh triển khai chi tiết được trình bày trong tài liệu hướng dẫn.

## Phạm vi
Repository tập trung vào các kịch bản được trình bày trong báo cáo và phần mô hình Decision Tree. Các kết quả thực nghiệm được trình bày cùng dữ liệu hoặc minh chứng tương ứng; nội dung mô tả không thay thế cho log, PCAP hay ảnh chụp thực tế.

## Cấu trúc một kịch bản
Mỗi kịch bản được tổ chức theo các thành phần phù hợp với nội dung thực nghiệm:
- Mô tả mục tiêu và điều kiện thử nghiệm.
- Lệnh hoặc mã mô phỏng hành vi.
- Quy tắc Suricata được sử dụng.
- Dữ liệu PCAP và log khi có.
- Minh chứng và nhận xét kết quả.

## Lưu ý sử dụng
Chỉ thực hiện các thử nghiệm trong môi trường lab được phép. Không chạy các lệnh mô phỏng tấn công trên hệ thống hoặc mạng không thuộc quyền kiểm soát của người thực hiện.
