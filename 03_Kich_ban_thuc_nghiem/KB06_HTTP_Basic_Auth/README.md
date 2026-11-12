> **Hướng dẫn người đọc:** README này mô tả mục tiêu, môi trường, thứ tự tái lập và cách kiểm tra kết quả. Hãy đọc phần môi trường và lệnh trước khi chạy script; cập nhật IP/interface theo lab của bạn. Chỉ chạy trong mạng ảo được phép.

# KB06 – HTTP Basic Authentication Brute Force

## 1. Giới thiệu

Kịch bản KB06 – HTTP Basic Authentication Brute Force mô phỏng hành vi dò đoán mật khẩu đối với tài nguyên web được bảo vệ bằng cơ chế HTTP Basic Authentication.

Trong kịch bản, máy Attacker sử dụng công cụ THC Hydra để gửi nhiều yêu cầu xác thực đến tài nguyên `/secure/` trên máy Victim. Các lần xác thực không thành công nhận được phản hồi HTTP 401 Unauthorized, trong khi thông tin xác thực hợp lệ nhận được phản hồi HTTP 200 OK.

Lưu lượng mạng phát sinh được thu thập bằng tcpdump dưới dạng PCAP và phân tích bằng Suricata nhằm đánh giá khả năng phát hiện của bộ luật ET Open và luật tùy chỉnh.

**Mục tiêu thực hiện:**
- Mô phỏng hành vi HTTP Basic Authentication Brute Force bằng Hydra.
- Thu thập và phân tích lưu lượng HTTP trên cổng TCP/80.
- Đánh giá khả năng phát hiện của bộ luật ET Open.
- Kiểm tra hiệu quả của luật tùy chỉnh SID 1000014.
- Đánh giá khả năng phân biệt giữa các yêu cầu xác thực thất bại và truy cập hợp lệ.

**Thông tin kịch bản:**
- MITRE ATT&CK: T1110.001 – Password Guessing.
- Công cụ kiểm thử: THC Hydra.
- Dịch vụ đích: HTTP Basic Authentication.
- Hệ thống giám sát: Suricata 8.0.3 RELEASE.
- Luật tùy chỉnh: SID 1000014 – LAB BRUTE HTTP basic auth many 401.

## 2. Môi trường thực nghiệm

| Thành phần | Địa chỉ / thông tin | Vai trò |
|---|---|---|
| Attacker | 192.168.190.131/24 | Thực hiện kiểm thử bằng Hydra |
| Victim | 192.168.190.130/24 | Chạy Apache HTTP Server và Suricata |
| Giao diện mạng | ens37 | Kết nối mạng lab |
| Dịch vụ đích | TCP/80 (HTTP) | Dịch vụ được kiểm thử |
| Tài nguyên bảo vệ | /secure/ | HTTP Basic Authentication |
| Tài khoản thử nghiệm | http_test | Tài khoản xác thực |

## 3. Quy trình triển khai

### Bước 1. Kiểm tra môi trường và cấu hình Suricata

Trên máy Victim, kiểm tra địa chỉ mạng, trạng thái Suricata và các thông số cấu hình cần thiết.

```bash
ip -br -4 addr
sudo systemctl status suricata
```

Kiểm tra thư mục lưu trữ luật, HOME_NET, giao diện AF_PACKET và danh sách rule-files:

```bash
sudo ls -lh /var/lib/suricata/rules/

sudo grep -n -A 15 'rule-files:' /etc/suricata/suricata.yaml

sudo grep -n 'default-rule-path:' /etc/suricata/suricata.yaml

sudo grep -n -A 12 'af-packet:' /etc/suricata/suricata.yaml

sudo grep -n -A 8 'HOME_NET:' /etc/suricata/suricata.yaml
```

Kết quả thực nghiệm: Victim sử dụng địa chỉ `192.168.190.130/24` trên giao diện `ens37`. Suricata 8.0.3 RELEASE hoạt động ở trạng thái active (running). HOME_NET được cấu hình theo địa chỉ Victim, giao diện AF_PACKET là ens37 và rule-files bao gồm suricata.rules cùng local.rules.

<img width="1181" height="405" alt="image" src="https://github.com/user-attachments/assets/fd944c8d-8f8a-4d6a-977d-b9441518af0b" />

### Bước 2. Xác nhận luật tự xây dựng

Kiểm tra luật SID 1000014 trong file local.rules:

```bash
sudo grep '1000014' /var/lib/suricata/rules/local.rules
```

Luật được sử dụng:

```text
alert http $HOME_NET any -> any any (msg:"LAB BRUTE HTTP basic auth many 401"; flow:established,from_server; http.stat_code; content:"401"; threshold:type both, track by_dst, count 5, seconds 60; classtype:attempted-admin; sid:1000014; rev:1;)
```

Luật sử dụng mã trạng thái HTTP 401 Unauthorized để nhận diện các phản hồi xác thực thất bại từ máy chủ. Ngưỡng thử nghiệm được thiết lập là 5 lần trong 60 giây.

<img width="1210" height="72" alt="image" src="https://github.com/user-attachments/assets/3e51f54e-1a72-4786-9d58-28864f6ffec6" />


### Bước 3. Run 1 – Kiểm tra bằng ET Open

Tạo bản sao cấu hình Suricata và vô hiệu hóa local.rules để Run 1 chỉ sử dụng bộ luật ET Open.

```bash
mkdir -p ~/kb08-run1

sudo cp /etc/suricata/suricata.yaml /tmp/kb08-run1.yaml

sudo sed -i '/^[[:space:]]*-[[:space:]]*local\.rules[[:space:]]*$/s/^/#/' /tmp/kb08-run1.yaml

sudo grep -n -A 3 '^rule-files:' /tmp/kb08-run1.yaml

sudo suricata -T -c /tmp/kb08-run1.yaml
```

Sau khi kiểm tra cấu hình thành công, tiến hành khởi chạy Suricata và thu thập lưu lượng HTTP.

**Trên Victim – khởi chạy Suricata:**

```bash
sudo systemctl stop suricata

sudo suricata -c /tmp/kb08-run1.yaml -i ens37 -l /home/nhung/kb08-run1
```

**Trên Victim – bắt lưu lượng HTTP:**

```bash
sudo tcpdump -i ens37 -nn \
'host 192.168.190.131 and tcp port 80' \
-w ~/kb08-run1/kb08-run1.pcap
```

**Trên Attacker – thực hiện kiểm thử:**

```bash
~/attack.sh
```

Sau khi Hydra hoàn tất, nhấn `Ctrl + C` để dừng tcpdump.

Kiểm tra kết quả cảnh báo Run 1:

```bash
sudo grep -a '"event_type":"alert"' \
~/kb08-run1/result/eve.json | wc -l

sudo cat ~/kb08-run1/result/fast.log

sudo grep -a '"event_type":"alert"' \
~/kb08-run1/result/eve.json \
| grep -o '"signature_id":[0-9]*' \
| sort | uniq -c
```

Kết quả thực nghiệm: Run 1 ghi nhận 46 cảnh báo, gồm:
- 1 cảnh báo SID 2011497 – ET SCAN Hydra User-Agent.
- 45 cảnh báo SID 2200074 – SURICATA TCPv4 invalid checksum.

Trong đó, SID 2011497 là cảnh báo liên quan đến dấu hiệu sử dụng Hydra; SID 2200074 là cảnh báo kiểm tra checksum TCP, không phản ánh trực tiếp hành vi HTTP Basic Authentication Brute Force.

<img width="1204" height="203" alt="image" src="https://github.com/user-attachments/assets/bb1a4359-6dab-435a-a507-091ee392dba7" />
<img width="1200" height="130" alt="image" src="https://github.com/user-attachments/assets/91e60744-135d-4137-b0af-52ba560533d6" />
<img width="1206" height="77" alt="image" src="https://github.com/user-attachments/assets/21dcad0a-083c-4267-a096-3487283b0840" />

### Bước 4. Run 2 – Kiểm tra bằng ET Open kết hợp luật tùy chỉnh

Tạo bản sao cấu hình Run 2, bảo đảm cả suricata.rules và local.rules đều được bật.

```bash
mkdir -p ~/kb08-run2

sudo cp /etc/suricata/suricata.yaml /tmp/kb08-run2.yaml

grep -n -A 3 '^rule-files:' /tmp/kb08-run2.yaml

sudo grep '1000014' /var/lib/suricata/rules/local.rules

sudo suricata -T -c /tmp/kb08-run2.yaml
```

Khởi chạy Suricata Run 2 trên Victim:

```bash
sudo systemctl stop suricata

sudo suricata -c /tmp/kb08-run2.yaml \
-i ens37 -l /home/nhung/kb08-run2
```

Trên một terminal khác của Victim, bắt lưu lượng HTTP:

```bash
sudo tcpdump -i ens37 -nn \
'host 192.168.190.131 and tcp port 80' \
-w ~/kb08-run2/kb08-run2.pcap
```

Trên Attacker, thực hiện lại kịch bản:

```bash
~/attack.sh
```

Sau khi Hydra hoàn tất, dừng tcpdump bằng `Ctrl + C`.

Kiểm tra kết quả cảnh báo:

```bash
sudo grep '"event_type":"alert"' \
~/kb08-run2/eve.json | wc -l

sudo grep '1000014' ~/kb08-run2/fast.log

sudo grep '"signature_id":1000014' \
~/kb08-run2/eve.json
```

Kết quả thực nghiệm: Run 2 ghi nhận tổng cộng 7 cảnh báo, trong đó SID 1000014 xuất hiện 3 lần.

Thông tin cảnh báo:
- Signature: LAB BRUTE HTTP basic auth many 401.
- Category: Attempted Administrator Privilege Gain.
- Severity: 1.
- Nguồn: 192.168.190.130:80.
- Đích: 192.168.190.131:47002.
- HTTP method/status: GET / 401.
- URL: /secure/.
- User-Agent: Mozilla/4.0 (Hydra).

Kết quả cho thấy luật tùy chỉnh có khả năng nhận diện các phản hồi HTTP 401 lặp lại trong quá trình kiểm thử.

<img width="1205" height="617" alt="image" src="https://github.com/user-attachments/assets/0e5d3091-52ad-486c-a4af-9f49db8696c7" />

### Bước 5. Đánh giá độ trễ phát hiện

Đọc file PCAP Run 2 để xác định thời điểm phản hồi HTTP 401 thứ 5:

```bash
tcpdump -nn -tttt -A \
-r ~/kb08-run2/kb08-run2.pcap \
'tcp port 80' \
| grep -B 2 -A 2 '401 Unauthorized'
```

Đối chiếu thời điểm phản hồi HTTP 401 thứ 5 với timestamp cảnh báo SID 1000014 trong eve.json.

Kết quả ghi nhận:
- Thời điểm phản hồi HTTP 401 thứ 5: 20:58:38.779113.
- Thời điểm cảnh báo SID 1000014: 20:58:39.325768.

Độ trễ phát hiện được tính:

```text
20:58:39.325768 - 20:58:38.779113
= 0.546655 giây
≈ 0.547 giây
```

Đây là kết quả của một lượt đo thực nghiệm.

### Bước 6. Kiểm thử Benign – Lưu lượng truy cập hợp lệ

Thực hiện kiểm thử bằng các yêu cầu HTTP hợp lệ để đánh giá khả năng phát sinh cảnh báo nhầm.

**Trên Victim – bắt lưu lượng:**

```bash
sudo tcpdump -i ens37 -nn \
'host 192.168.190.131 and tcp port 80' \
-w ~/kb08-run2/kb08-benign.pcap
```

**Trên Attacker – gửi 10 yêu cầu truy cập hợp lệ:**

```bash
for i in $(seq 1 10); do
  curl -s -o /dev/null \
  -w "Request $i: HTTP %{http_code}\n" \
  -u http_test:password123 \
  http://192.168.190.130/secure/
  sleep 1
done
```

Sau khi hoàn tất, dừng tcpdump trên Victim bằng `Ctrl + C`.

Kiểm tra số lượng cảnh báo SID 1000014:

```bash
sudo grep '"signature_id":1000014' \
~/kb08-run2/eve.json | wc -l

ls -lh ~/kb08-run2/kb08-benign.pcap
```

Kết quả thực nghiệm:
- 10/10 yêu cầu truy cập hợp lệ nhận được HTTP 200.
- PCAP Benign ghi nhận 100 packets received by filter và 0 packets dropped by kernel.
- Số lượng cảnh báo SID 1000014 vẫn là 3, không tăng sau khi thực hiện kiểm thử Benign.

Như vậy, trong mẫu 10 yêu cầu hợp lệ được kiểm tra, luật tùy chỉnh SID 1000014 không phát sinh thêm cảnh báo. Kết quả này chỉ phản ánh mẫu thử nghiệm đã thực hiện, không khẳng định tỷ lệ false positive bằng 0 trong mọi trường hợp.

<img width="1200" height="262" alt="image" src="https://github.com/user-attachments/assets/328cbf5b-28a9-4ec0-bbee-3524875501b5" />

<img width="1205" height="227" alt="image" src="https://github.com/user-attachments/assets/9d3c2fdd-f4ec-4410-bb85-21bfb4d8c017" />

### Bước 7. Kiểm tra và lưu trữ kết quả

Kiểm tra các tệp kết quả được lưu trong hai thư mục Run 1 và Run 2:

```bash
ls -lh ~/kb08-run1/

ls -lh ~/kb08-run2/
```

Các tệp kết quả bao gồm:

| Thư mục | Tệp | Mục đích |
|---|---|---|
| kb08-run1 | kb08-run1.pcap | Lưu lưu lượng Run 1 |
| kb08-run1 | eve.json, fast.log | Lưu sự kiện và cảnh báo Run 1 |
| kb08-run1 | stats.log, suricata.log | Lưu thống kê và nhật ký Suricata |
| kb08-run2 | kb08-run2.pcap | Lưu lưu lượng Run 2 |
| kb08-run2 | kb08-benign.pcap | Lưu lưu lượng lành tính |
| kb08-run2 | eve.json, fast.log | Lưu sự kiện và cảnh báo Run 2 |
| kb08-run2 | stats.log, suricata.log | Lưu thống kê và nhật ký Suricata |

## 4. Tổng hợp kết quả

| Tiêu chí | Kết quả |
|---|---|
| Mạng lab | Attacker 192.168.190.131; Victim 192.168.190.130 |
| HTTP Basic Authentication | 401 khi xác thực thất bại; 200 khi hợp lệ |
| Hydra | 10 lần thử, tìm được 1 mật khẩu hợp lệ |
| Run 1 – ET Open | 46 alert |
| SID 2011497 | 1 alert – ET SCAN Hydra User-Agent |
| SID 2200074 | 45 alert – Invalid checksum |
| Run 2 – Kết hợp luật | 7 alert tổng |
| SID 1000014 | 3 alert – HTTP Basic Auth many 401 |
| Độ trễ phát hiện | Khoảng 0,547 giây |
| Benign | 10/10 request HTTP 200 |
| False positive quan sát | Không phát sinh thêm alert SID 1000014 trên 10 request hợp lệ |

## 5. Kết luận

Kịch bản KB06 đã mô phỏng được hành vi HTTP Basic Authentication Brute Force trong môi trường mạng lab. Máy Attacker sử dụng Hydra gửi các yêu cầu xác thực đến tài nguyên `/secure/` trên Victim. Hydra thực hiện 10 lần thử và tìm được một thông tin xác thực hợp lệ.

Trong Run 1, bộ luật ET Open ghi nhận một cảnh báo SID 2011497 liên quan đến dấu hiệu sử dụng Hydra, bên cạnh các cảnh báo checksum. Khi bổ sung luật tùy chỉnh SID 1000014, Run 2 ghi nhận ba cảnh báo liên quan đến các phản hồi HTTP 401 lặp lại.

Kết quả kiểm thử Benign cho thấy 10 yêu cầu truy cập hợp lệ đều nhận được HTTP 200 và không làm tăng số lượng cảnh báo SID 1000014. Độ trễ phát hiện ghi nhận khoảng 0,547 giây trong một lượt đo.

Nhìn chung, kịch bản đã thể hiện khả năng sử dụng Suricata kết hợp bộ luật ET Open và luật tùy chỉnh để giám sát các hoạt động xác thực HTTP. Tuy nhiên, các kết quả về độ trễ và false positive mới được đánh giá trên số lượng mẫu thử nghiệm giới hạn, cần tiếp tục kiểm thử với nhiều lượt và điều kiện lưu lượng khác nhau để có đánh giá toàn diện hơn.

## Tệp nguồn và minh chứng gốc

Thư mục nguồn trong repository ban đầu: [`08-http-basic-auth-bruteforce`](https://github.com/phanyen206/Suricata/tree/main/scenarios/08-http-basic-auth-bruteforce). Các tệp nhị phân như PCAP, ảnh chụp, gói minh chứng hoặc tài liệu DOCX (nếu có) hiện vẫn được giữ tại repository nguồn; README này liên kết về nguồn để người đọc tải/xem, không thay thế bằng dữ liệu giả.
