# Hướng dẫn cài đặt môi trường thực nghiệm và Suricata

## 1. Mục tiêu và phạm vi

Tài liệu hướng dẫn dựng hai máy ảo Ubuntu để tái lập các bài kiểm thử IDS trong mạng lab. Máy **Attacker** tạo lưu lượng kiểm thử; máy **Victim** cung cấp dịch vụ đích, thu thập PCAP và chạy Suricata. Chỉ thực hiện các thử nghiệm trong mạng ảo do người thực hiện quản lý hoặc được cho phép.

Cấu hình nền được mô tả theo môi trường VMware Workstation của nhóm: mỗi máy ảo ban đầu được cấp 4 GB RAM và ổ đĩa 40 GB. Có thể điều chỉnh theo tài nguyên máy thật, nhưng cần bảo đảm đủ dung lượng cho hệ điều hành, công cụ và dữ liệu PCAP.

## 2. Chuẩn bị VMware và Ubuntu

1. Cài VMware Workstation trên máy chủ.
2. Tải ISO Ubuntu phù hợp và tạo máy ảo nền có tên `Ubuntu_Base_Template`.
3. Cài Ubuntu, cập nhật hệ thống và cài VMware Tools/open-vm-tools nếu cần.
4. Tắt máy ảo nền, dùng **Full Clone** tạo hai máy độc lập: `Ubuntu-Attacker` và `Ubuntu-Victim`.
5. Đặt hostname riêng cho từng máy để tránh nhầm lẫn khi chụp ảnh và thu thập log.

Không dùng đồng thời một máy ảo clone chung một địa chỉ MAC/IP tĩnh. Sau khi clone, kiểm tra hostname, địa chỉ IP và giao diện mạng trên từng máy.

## 3. Cấu hình mạng

### 3.1. Mô hình Host-only kết hợp NAT

Cấu hình nền được ghi nhận trong tài liệu thực nghiệm:

| Máy | Host-only (VMnet1) | NAT (VMnet8) |
|---|---|---|
| Attacker | `192.168.100.10/24`, thường là `ens37` | thường là `ens33` |
| Victim | `192.168.100.20/24`, thường là `ens37` | thường là `ens33` |

- **Host-only / VMnet1:** mạng riêng để Attacker và Victim trao đổi lưu lượng kiểm thử.
- **NAT / VMnet8:** cung cấp Internet cho việc cập nhật hệ điều hành và gói phần mềm.
- Tên interface có thể khác giữa các bản Ubuntu hoặc cấu hình VM. Không mặc định `ens33`/`ens37`; xác định lại bằng lệnh thực tế.

Trên cả hai máy:

```bash
ip -br addr
ip route
hostname
```

Trên Attacker, kiểm tra kết nối đến Victim (thay interface nếu máy bạn khác):

```bash
ip -4 addr show dev ens37
ping -c 4 192.168.100.20
```

Trên Victim:

```bash
ip -4 addr show dev ens37
ping -c 4 192.168.100.10
```

Chỉ chuyển sang bước tiếp theo khi hai máy có thể liên lạc qua mạng lab. Nếu ping không thành công, kiểm tra VMnet, chế độ card mạng, địa chỉ IP, subnet mask và firewall.

### 3.2. Khác biệt giữa các kịch bản

Không phải mọi KB đều dùng cùng một kiểu kết nối hoặc cùng tên interface. Một số KB ghi nhận mạng LAN Segment và interface `ens33`/ `enp0s3`; một số KB dùng Host-only `ens37`. Một số phép thử phân tích PCAP offline thay vì bắt lưu lượng trực tiếp.

Vì vậy, cấu hình ở mục 3.1 là mô hình nền; **README của từng KB là căn cứ cuối cùng** về IP, interface, vị trí bắt gói và phương thức chạy Suricata. Không thay IP/interface của KB bằng ví dụ trong tài liệu này nếu chưa đối chiếu topology của chính KB đó.

## 4. Cài đặt Suricata trên Victim

### 4.1. Kiểm tra hệ thống và mạng

```bash
hostname
ip -br addr
ip route
```

Đảm bảo Victim có kết nối Internet qua NAT trước khi cài gói. Trong mô hình nền, interface Host-only nhận lưu lượng lab; NAT dùng cho truy cập Internet.

### 4.2. Cài Suricata và jq

```bash
sudo apt update
sudo apt install suricata jq -y
```

Kiểm tra phiên bản và thông tin build:

```bash
suricata -V
suricata --build-info
jq --version
```

Môi trường được mô tả trong báo cáo sử dụng **Suricata 8.0.3**. Phiên bản cài từ kho Ubuntu có thể khác tùy thời điểm và phiên bản hệ điều hành; nếu cần tái lập đúng kết quả, phải ghi nhận phiên bản thực tế bằng `suricata -V`, không tự ghi phiên bản mong muốn.

### 4.3. Cập nhật và kiểm tra bộ luật

Các đường dẫn cấu hình thường dùng trong môi trường này:

- Tệp cấu hình: `/etc/suricata/suricata.yaml`
- Tệp luật: `/var/lib/suricata/rules/suricata.rules`
- Thư mục log: `/var/log/suricata/`

Kiểm tra cấu hình và bộ luật hiện có:

```bash
sudo suricata -T -v -c /etc/suricata/suricata.yaml
```

Nếu môi trường đã cài công cụ `suricata-update`, có thể kiểm tra và cập nhật nguồn luật theo cấu hình của máy:

```bash
sudo suricata-update
```

Sau khi cập nhật, chạy lại lệnh kiểm tra cấu hình. Không khẳng định bộ luật đã được cập nhật thành công nếu máy không truy cập được máy chủ nguồn; trong trường hợp đó cần ghi rõ đang dùng bộ luật có sẵn/cache và kiểm tra timestamp/tệp luật thực tế.

### 4.4. Cấu hình HOME_NET và interface

Mở tệp cấu hình:

```bash
sudo nano /etc/suricata/suricata.yaml
```

Kiểm tra các mục `HOME_NET`, `EXTERNAL_NET`, `default-rule-path`, `rule-files` và cấu hình EVE JSON. Với mạng nền `192.168.100.0/24`, HOME_NET phải phản ánh đúng subnet thực tế. Không thay toàn bộ cấu hình bằng một đoạn mẫu không tương thích với phiên bản đang cài.

Xem nhanh các mục liên quan:

```bash
sudo grep -n -A8 -E 'HOME_NET:|EXTERNAL_NET:|rule-files:|default-rule-path:' /etc/suricata/suricata.yaml
```

Nếu chạy IDS trực tiếp trên interface, phải chỉ định đúng interface mà lưu lượng kiểm thử đi qua/được mirror tới. Cài Suricata trên Victim không tự động bảo đảm nó nhìn thấy mọi gói tin giữa hai máy; cần xác nhận đường đi và khả năng quan sát thực tế.

### 4.5. Kiểm tra dịch vụ và nhật ký

```bash
sudo systemctl status suricata --no-pager
sudo systemctl is-active suricata
sudo ls -lh /var/log/suricata/
```

Các tệp thường dùng:

- `fast.log`: cảnh báo dạng văn bản.
- `eve.json`: sự kiện JSON, có thể lọc/thống kê bằng `jq`.

Ví dụ xem cảnh báo:

```bash
sudo tail -n 20 /var/log/suricata/fast.log
sudo jq 'select(.event_type == "alert") | {timestamp, src_ip, dest_ip, alert}' /var/log/suricata/eve.json
```

Kiểm tra cấu hình lần cuối:

```bash
sudo suricata -T -v -c /etc/suricata/suricata.yaml
```

## 5. Nạp luật tùy chỉnh trong từng KB

Luật đối chứng và luật tùy chỉnh phải được giữ tách biệt để phép so sánh có ý nghĩa. Đọc README của KB để biết chính xác dùng tùy chọn nào.

- `-S <file>`: sử dụng tệp luật được chỉ định thay cho bộ luật mặc định.
- `-s <file>`: nạp thêm tệp luật vào bộ luật hiện có.

Không tự ý đổi `-S` thành `-s` hoặc ngược lại. Kiểm tra cú pháp luật và cấu hình trước khi chạy thực nghiệm. SID phải được quản lý nhất quán, tránh trùng SID giữa các luật tự viết.

## 6. Chạy Suricata trực tiếp hoặc phân tích PCAP

Tùy từng KB, Suricata có thể giám sát interface hoặc phân tích PCAP offline. Ví dụ cú pháp tổng quát:

Giám sát interface (thay `ens37` bằng interface thực tế):

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i ens37
```

Phân tích PCAP offline:

```bash
sudo suricata -r sample.pcap -c /etc/suricata/suricata.yaml
```

Các KB có thể bổ sung tham số như `-k none`, `-S` hoặc `-s`; chỉ sử dụng đúng lệnh đã được mô tả trong KB tương ứng. Khi so sánh Run 1 và Run 2, giữ nguyên PCAP và các tham số xử lý; chỉ thay đổi thành phần luật đang được đánh giá.

## 7. Checklist trước khi thực hiện kịch bản

- [ ] Hai máy ảo khởi động độc lập, hostname phân biệt.
- [ ] IP và subnet của Attacker/Victim đúng với README KB.
- [ ] Đúng interface và đúng loại mạng (Host-only, LAN Segment hoặc cấu hình riêng của KB).
- [ ] Attacker liên lạc được với Victim nếu KB cần kết nối trực tiếp.
- [ ] Dịch vụ đích của KB đang hoạt động và đúng cổng.
- [ ] Suricata chạy đúng phiên bản; cấu hình kiểm tra thành công bằng `suricata -T`.
- [ ] Đã xác định đúng ruleset và tệp luật cần dùng cho Run 1/Run 2.
- [ ] Thư mục lưu PCAP và log tồn tại, có đủ quyền ghi và đủ dung lượng.
- [ ] Chỉ chạy lưu lượng thử nghiệm trong mạng lab được phép.

## 8. Lưu ý về tính tái lập

Các thông số trong tài liệu được tổng hợp từ cấu hình và quy trình thực nghiệm của nhóm. Môi trường có thể thay đổi theo phiên bản Ubuntu, VMware, tên interface, trạng thái dịch vụ và khả năng truy cập nguồn luật. Khi tái lập, hãy lưu lại đầu ra lệnh kiểm tra, phiên bản phần mềm, cấu hình mạng và lệnh Suricata thực tế; không suy diễn rằng một cấu hình đã hoạt động chỉ vì lệnh cài đặt đã chạy.
