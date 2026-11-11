> **Hướng dẫn người đọc:** README này mô tả mục tiêu, môi trường, thứ tự tái lập và cách kiểm tra kết quả. Hãy đọc phần môi trường và lệnh trước khi chạy script; cập nhật IP/interface theo lab của bạn. Chỉ chạy trong mạng ảo được phép.

# Kịch bản 12 – Phát hiện UDP tần suất cao bằng Suricata

## 1. Mục tiêu và bài toán

Thực nghiệm cơ chế cảnh báo UDP tần suất cao trên mạng lab riêng, đối chiếu bộ luật đối chứng cấu hình trên Victim với luật tự xây dựng. Bài toán: với luồng UDP từ **Attacker 192.168.100.10** đến **Victim 192.168.100.20**, cổng **9999**, nhận biết lưu lượng tăng đột biến (100 gói gửi cách nhau khoảng 10 ms) nhưng không cảnh báo theo SID riêng với lưu lượng bình thường (5 gói cách nhau 1 giây). Đây là thử nghiệm *phát hiện tần suất UDP cao*, không phải phép đo chứng minh dịch vụ bị từ chối hoặc hệ thống bị quá tải.

## 2. Môi trường

| Vai trò | Máy / IP | Card |
|---|---|---|
| Attacker | Ubuntu, `192.168.100.10/24` | `ens37` – VMware VMnet1 Host-only |
| Victim | Ubuntu, `192.168.100.20/24` | `ens37` – VMware VMnet1 Host-only |
| Cập nhật Internet | NAT, `ens33` trên mỗi máy | VMnet8 |
| IDS | Suricata 8.0.3 trên Victim | Phân tích PCAP offline |
| Luật đối chứng | `/var/lib/suricata/rules/suricata.rules` qua `suricata.yaml` | Bộ có các chữ ký ET đã kiểm tra |

`suricata-update` đã được sử dụng trên Victim trước đó; không tự ý cập nhật phiên bản luật giữa các Run. Kiểm tra cấu hình và mã băm khi cần: `sudo suricata -T -v -c /etc/suricata/suricata.yaml` và `sha256sum /var/lib/suricata/rules/suricata.rules`. Các bằng chứng chữ ký ET không tự xác nhận lịch sử tải toàn bộ file luật. Các Run `-s custom-rule.rules` **bổ sung luật riêng vào bộ luật cấu hình**, không phải chỉ chạy duy nhất luật riêng; vì vậy đối chiếu **SID 1000015** riêng với tổng alert.

## 3. Luật riêng và cách hoạt động

File `custom-rule.rules`:

```suricata
alert udp 192.168.100.10 any -> 192.168.100.20 9999 (msg:"LAB UDP Flood - High Rate"; detection_filter:track by_src, count 20, seconds 1; classtype:attempted-dos; sid:1000015; rev:2;)
```

- `alert udp`: phát sinh cảnh báo với gói UDP khớp luật.
- `192.168.100.10 any -> 192.168.100.20 9999`: giới hạn IP nguồn, IP đích và cổng đích theo mô hình nhóm.
- `detection_filter:track by_src, count 20, seconds 1`: theo dõi tần suất theo IP nguồn; khi vượt ngưỡng thì có thể tạo nhiều cảnh báo với các gói tiếp theo. Số alert không bằng số cuộc tấn công.
- `classtype:attempted-dos`: phân loại cảnh báo; `sid:1000015` định danh luật; `rev:2` là bản đã giới hạn IP.

Kiểm tra luật trên Victim:

```bash
cd ~/scenarios/12-udp-flood
cat custom-rule.rules
sudo suricata -T -c /etc/suricata/suricata.yaml -s custom-rule.rules
```

![Luật riêng và kiểm tra cú pháp](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/12-udp-flood/01-luat-udp.png)

*Hình 1. Nội dung luật UDP và kiểm tra cấu hình hợp lệ.*

## 4. Chuẩn bị, thu thập PCAP trên mạng VMnet1

Trên hai máy, kiểm tra `ip -br addr` và ping kiểm tra kết nối. **Chỉ dùng trong môi trường lab thuộc quyền kiểm soát**, không chạy ngoài mạng được phép. Cài sẵn `tcpdump` trên Victim, `hping3` và `python3` trên Attacker.

### 4.1. Thu 100 gói UDP tần suất cao

**Victim – Terminal 1:**

```bash
cd ~/scenarios/12-udp-flood
sudo tcpdump -i ens37 -nn -w sample_group.pcap 'udp and src host 192.168.100.10 and dst host 192.168.100.20 and dst port 9999'
```

**Attacker – Terminal khác:**

```bash
sudo hping3 --udp -c 100 -i u10000 -p 9999 192.168.100.20
```

Quay về Victim, `Ctrl+C` để dừng `tcpdump`. Sau đó:

```bash
tcpdump -nn -r sample_group.pcap -c 5
tcpdump -nn -r sample_group.pcap 'udp and dst port 9999' 2>/dev/null | wc -l
```

Kết quả đã ghi nhận: **100 gói UDP**, nguồn `192.168.100.10` đến đích `192.168.100.20:9999`.

![100 gói UDP đến đúng địa chỉ](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/12-udp-flood/02-pcap-100-udp.png)

*Hình 2. Xác minh IP, cổng đích và số gói trong sample_group.pcap.*

### 4.2. Thu 5 gói UDP bình thường

Trong lần thực nghiệm, `hping3` gửi UDP tới cổng không có listener có thể chờ phản hồi ICMP Port Unreachable, nên mẫu bình thường được tạo bằng Python `socket.sendto()` (không có yêu cầu phản hồi), cách nhau 1 giây.

**Victim – bắt đầu ghi vào file mới:**

```bash
sudo tcpdump -i ens37 -nn -w normal_group_new.pcap 'udp and src host 192.168.100.10 and dst host 192.168.100.20 and dst port 9999'
```

**Attacker – chạy script:**

```bash
bash normal.sh
```

Hoặc thực thi trực tiếp nội dung Python của `normal.sh`. Sau khi gửi đủ 5/5 gói, dừng `tcpdump` bằng `Ctrl+C`, rồi kiểm tra:

```bash
tcpdump -nn -r normal_group_new.pcap -c 5
tcpdump -nn -r normal_group_new.pcap 2>/dev/null | wc -l
```

Kết quả đã ghi nhận: **5 gói UDP**, mỗi gói mang **15 byte** dữ liệu, cách nhau khoảng 1 giây.

![Attacker gửi năm gói UDP](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/12-udp-flood/05-gui-5-udp.png)

*Hình 3. Python gửi đủ 5/5 gói UDP bình thường.*

![Victim đọc năm gói UDP](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/12-udp-flood/06-pcap-5-udp.png)

*Hình 4. Xác minh năm gói UDP tại Victim.*

## 5. Kiểm thử bốn lần trên Victim

Chạy từ `~/scenarios/12-udp-flood`; dùng thư mục log riêng và **không chạy lại vào cùng thư mục log cũ** (tránh cộng dồn alert). Các lệnh có `-s custom-rule.rules` nạp thêm luật riêng bên cạnh luật trong cấu hình mặc định.

### Run 1 – sample_group.pcap, bộ luật đối chứng

```bash
mkdir -p run1_group
sudo suricata -r sample_group.pcap -c /etc/suricata/suricata.yaml -l run1_group
jq -s '[.[] | select(.event_type=="alert")] | length' run1_group/eve.json
```

**Thực tế: đọc 100 gói, tổng 0 cảnh báo.**

![Run 1](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/12-udp-flood/03-run1-et-open.png)

*Hình 5. Run 1 – kiểm thử 100 gói UDP với bộ luật cấu hình.*

### Run 2 – sample_group.pcap, nạp thêm luật riêng

```bash
mkdir -p run2_group
sudo suricata -r sample_group.pcap -c /etc/suricata/suricata.yaml -s custom-rule.rules -l run2_group
jq -s '[.[] | select(.event_type=="alert" and .alert.signature_id==1000015)] | length' run2_group/eve.json
```

**Thực tế: đọc 100 gói, 79 cảnh báo riêng SID 1000015.**

![Run 2](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/12-udp-flood/04-run2-custom.png)

*Hình 6. Run 2 – luật riêng phát sinh 79 cảnh báo.*

### Run 3 – normal_group_new.pcap, bộ luật đối chứng

**Chú ý:** Không dùng lại file `normal_group.pcap` từng chỉ chứa 1 gói. Mẫu chính thức của nhóm là `normal_group_new.pcap` chứa đủ **5 gói**.

```bash
mkdir -p run3_group_fixed
sudo suricata -r normal_group_new.pcap -c /etc/suricata/suricata.yaml -l run3_group_fixed
jq -s '[.[] | select(.event_type=="alert")] | length' run3_group_fixed/eve.json
```

**Thực tế: đọc 5 gói, tổng 0 cảnh báo.**

![Run 3](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/12-udp-flood/07-run3-et-open.png)

*Hình 7. Run 3 – 5 gói UDP bình thường, không có cảnh báo.*

### Run 4 – normal_group_new.pcap, nạp thêm luật riêng

```bash
mkdir -p run4_group_fixed
sudo suricata -r normal_group_new.pcap -c /etc/suricata/suricata.yaml -s custom-rule.rules -l run4_group_fixed
jq -s '[.[] | select(.event_type=="alert" and .alert.signature_id==1000015)] | length' run4_group_fixed/eve.json
```

**Thực tế: đọc 5 gói, 0 cảnh báo SID 1000015.**

![Run 4](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/12-udp-flood/08-run4-custom.png)

*Hình 8. Run 4 – luật riêng không cảnh báo trên 5 gói bình thường.*

## 6. Bảng kết quả và nhận xét

| Run | Mẫu dữ liệu | Cấu hình luật | Tổng / cảnh báo theo SID được đo |
|---|---|---|---:|
| 1 | 100 UDP tần suất cao | Bộ luật cấu hình (ET Open đối chứng) | **0 tổng** |
| 2 | 100 UDP tần suất cao | Bộ luật cấu hình + luật tùy chỉnh | **79 SID 1000015** |
| 3 | 5 UDP bình thường | Bộ luật cấu hình (ET Open đối chứng) | **0 tổng** |
| 4 | 5 UDP bình thường | Bộ luật cấu hình + luật tùy chỉnh | **0 SID 1000015** |

**Nhận xét:** Luật riêng đã phát sinh cảnh báo ở mẫu tần suất cao và không phát sinh cảnh báo ở mẫu UDP 5 gói cách nhau 1 giây. Đây là thử nghiệm hai mẫu nhỏ với thông số cố định; chưa đủ để suy ra độ chính xác/khả năng khái quát trong mạng thật, cũng chưa chứng minh có thiệt hại DoS. Phép thử trên PCAP cũng không cho thấy hiệu năng real-time của IDS.

## 7. Mã nguồn và cách chạy lại

Các file nằm **cùng cấp với README.md** và ảnh PNG, không cần thư mục `images/`:

| File | Chạy trên máy | Chức năng |
|---|---|---|
| `custom-rule.rules` | Victim | Luật phát hiện UDP, SID 1000015 rev:2 |
| `attack.sh` | Attacker | Gửi 100 UDP tần suất cao (hping3) |
| `normal.sh` | Attacker | Gửi 5 UDP bình thường (Python) |
| `capture.sh` | Victim | Bắt gói UDP và tạo file PCAP, chọn `attack`/`normal` |
| `run-tests.sh` | Victim | Kiểm tra luật, chạy 4 Run vào thư mục log có timestamp và in tổng/SID alert |
| `.gitignore` | GitHub | Loại trừ các PCAP và log chạy thử khỏi commit theo mặc định |

**Tái hiện từ đầu:** chạy `bash capture.sh attack` trên Victim, sau đó `bash attack.sh` trên Attacker; dừng capture bằng Ctrl+C. Tiếp tục `bash capture.sh normal` và `bash normal.sh`; dừng capture. Cuối cùng trên Victim chạy `bash run-tests.sh`. Các script có kiểm tra điều kiện cơ bản và tạo log trong thư mục riêng để không ghi đè kết quả cũ. Cần đảm bảo có công cụ `suricata`, `tcpdump`, `jq`, `hping3`, `python3` và kết nối VMnet1.

**PCAP gốc không có trong gói ZIP** vì nằm trên máy Victim. Để lưu PCAP minh chứng, có thể copy chúng từ Victim vào repo sau khi xem xét dung lượng và quy định nhóm; nếu muốn Git theo dõi PCAP, điều chỉnh `.gitignore`.



## Tệp nguồn và minh chứng gốc

Thư mục nguồn trong repository ban đầu: [`12-udp-flood`](https://github.com/phanyen206/Suricata/tree/main/scenarios/12-udp-flood). Các tệp nhị phân như PCAP, ảnh chụp, gói minh chứng hoặc tài liệu DOCX (nếu có) hiện vẫn được giữ tại repository nguồn; README này liên kết về nguồn để người đọc tải/xem, không thay thế bằng dữ liệu giả.
