# 01. Môi trường thực nghiệm

Thư mục này mô tả hạ tầng dùng để tái lập các kịch bản. Đọc tài liệu ở đây trước khi chạy bất kỳ script nào trong mục 03.

## Thành phần
- `So-do-mo-hinh-mang.md`: sơ đồ kết nối, vai trò Attacker/Victim và interface giám sát.
- Thông tin máy ảo, hệ điều hành và phiên bản phần mềm được ghi trong README của từng kịch bản nếu có khác biệt.

## Kiểm tra trước khi chạy
Trên cả hai máy Ubuntu, mở Terminal và chạy:

```bash
hostname
ip -br addr
ip route
```

Kiểm tra liên lạc giữa Attacker và Victim bằng địa chỉ IP trong README của KB:

```bash
ping -c 4 <IP_MAY_DOI_DIEN>
```

Không sao chép IP mẫu trong README một cách máy móc. IP và tên interface có thể khác khi clone VM hoặc chuyển sang VMware/VirtualBox khác. Các KB có thể dùng `ens33`, `enp0s3` hoặc interface khác; dùng đúng kết quả `ip -br addr` trên máy thực tế.

**Lưu ý:** Một số kịch bản được chạy trong môi trường khác nhau. Hãy ưu tiên phần “Môi trường” của chính KB đó khi có khác biệt.
