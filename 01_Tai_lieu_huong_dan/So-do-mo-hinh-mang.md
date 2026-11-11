# Sơ đồ mô hình mạng

Tài liệu này giúp người đọc xác định máy nào tạo lưu lượng, máy nào nhận lưu lượng và vị trí Suricata quan sát gói tin.

## Vai trò các máy
- **Attacker:** máy phát sinh lưu lượng mô phỏng trong phạm vi lab.
- **Victim:** máy cung cấp dịch vụ đích và/hoặc máy thu PCAP, chạy Suricata theo cấu hình của từng KB.
- **Suricata IDS:** tiến trình giám sát lưu lượng trực tiếp hoặc đọc PCAP offline; vị trí triển khai được mô tả ở từng KB.

## Kiểm tra trên máy đang sử dụng
```bash
hostname
ip -br addr
ip route
```

Dùng địa chỉ IP và interface hiển thị tại máy của bạn, không mặc định rằng địa chỉ trong ảnh hoặc script mẫu luôn đúng. Mô hình và IP của một số kịch bản khác nhau; xem README KB tương ứng trước khi thực hiện.
