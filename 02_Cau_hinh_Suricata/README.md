# 02. Cấu hình Suricata

Thư mục này chứa tài liệu cấu hình chung. Trước khi chạy kịch bản, hãy xác định Suricata đang đọc cấu hình nào, nạp ruleset nào và ghi log ở đâu.

## Kiểm tra phiên bản và cấu hình
```bash
suricata -V
sudo suricata -T -c /etc/suricata/suricata.yaml
```

Để xem cấu hình HOME_NET và rule-files:
```bash
sudo grep -n -A8 -E 'HOME_NET:|EXTERNAL_NET:|rule-files:' /etc/suricata/suricata.yaml
```

Để kiểm tra trạng thái dịch vụ:
```bash
sudo systemctl is-active suricata
sudo systemctl status suricata --no-pager
```

Các kịch bản có thể chạy offline bằng `suricata -r`, không nhất thiết dùng dịch vụ systemd. Hãy theo đúng lệnh của từng KB; không tự thay `-S` bằng `-s` hoặc ngược lại vì hai tùy chọn có ý nghĩa khác nhau.

## Luật
- Luật chung đã xác minh được đặt trong `Luat-chung/`.
- Luật riêng của KB nằm ngay trong thư mục kịch bản đó.
- Chỉ nạp luật mà README của KB chỉ định. Không ghép nhiều tệp luật tùy tiện.
