> **Hướng dẫn người đọc:** README này mô tả mục tiêu, môi trường, thứ tự tái lập và cách kiểm tra kết quả. Hãy đọc phần môi trường và lệnh trước khi chạy script; cập nhật IP/interface theo lab của bạn. Chỉ chạy trong mạng ảo được phép.

# KB06 – HTTP BASIC AUTH BRUTE FORCE

## 1. Thông tin nhiệm vụ

- **Người phụ trách:** Uyên
- **Tên kịch bản:** KB06 – HTTP Basic Auth Brute Force
- **Nhóm tấn công:** Mật khẩu (Password)
- **MITRE ATT&CK:** T1110.001 – Password Guessing
- **Công cụ kiểm thử:** THC Hydra
- **Công cụ giám sát và phát hiện:** Suricata 8.0.3 RELEASE
- **SID luật tự xây dựng:** 1000014

## 2. Mục tiêu thực hiện

Nhiệm vụ KB06 nhằm mô phỏng hành vi thử nhiều mật khẩu để đăng nhập vào tài nguyên được bảo vệ bằng HTTP Basic Authentication trên máy Victim, từ đó đánh giá khả năng phát hiện của hệ thống Suricata.

Các mục tiêu cụ thể:

- Thiết lập kết nối mạng giữa máy Attacker và Victim.
- Cài đặt và cấu hình Apache HTTP Server trên Victim.
- Thiết lập xác thực HTTP Basic Authentication cho đường dẫn `/secure/`.
- Tạo tài khoản thử nghiệm và kiểm tra khả năng xác thực.
- Sử dụng Hydra để mô phỏng hành vi thử nhiều mật khẩu trong môi trường lab.
- Xây dựng luật Suricata nhằm phát hiện các phản hồi HTTP 401 lặp lại.
- Đánh giá khả năng phát hiện của bộ luật ET Open và luật tự xây dựng.
- Kiểm tra cảnh báo trong nhật ký `eve.json` và `fast.log`.
- Đánh giá độ trễ phát hiện và kiểm tra cảnh báo sai bằng lưu lượng truy cập hợp lệ.

## 3. Môi trường thực nghiệm

Mô hình thực nghiệm sử dụng hai máy ảo Ubuntu được kết nối thông qua mạng LAN Segment trên VMware.

| Thành phần | Thông tin |
|---|---|
| Máy Attacker | Ubuntu |
| Địa chỉ IP Attacker | 192.168.190.131 |
| Máy Victim | Ubuntu |
| Địa chỉ IP Victim | 192.168.190.130 |
| Giao thức kiểm thử | HTTP/TCP |
| Cổng dịch vụ | 80 |
| Đường dẫn được bảo vệ | `/secure/` |
| Phương thức xác thực | HTTP Basic Authentication |
| Công cụ tấn công mô phỏng | THC Hydra |
| Công cụ phát hiện | Suricata 8.0.3 RELEASE |
| Web Server | Apache 2.4.66 |
| Tài khoản thử nghiệm | `http_test` |

## 4. Các bước triển khai thực nghiệm

### 4.1. Kiểm tra kết nối mạng giữa Attacker và Victim

Sau khi khởi động hai máy ảo, tiến hành kiểm tra địa chỉ IP và khả năng kết nối mạng.

Địa chỉ IP thực tế được sử dụng:

- Attacker: `192.168.190.131`
- Victim: `192.168.190.130`

Kết quả kiểm tra cho thấy hai máy có thể liên lạc với nhau thông qua mạng lab, không có gói tin bị mất trong lần kiểm tra được ghi nhận.

### 4.2. Cài đặt và kiểm tra Apache HTTP Server trên Victim

Trên máy Victim, tiến hành cài đặt Apache HTTP Server và kiểm tra trạng thái dịch vụ.

Lệnh kiểm tra:

```bash
sudo systemctl status apache2
```

Kiểm tra cấu hình Apache:

```bash
sudo apache2ctl configtest
```

Kết quả trả về `Syntax OK`, xác nhận cấu hình Apache hợp lệ.

Sau khi cấu hình, tiến hành nạp lại dịch vụ:

```bash
sudo systemctl reload apache2
```

Kết quả cho thấy Apache HTTP Server hoạt động bình thường trên máy Victim.

### 4.3. Cấu hình HTTP Basic Authentication

Thiết lập xác thực HTTP Basic Authentication cho tài nguyên tại đường dẫn `/secure/`.

Tạo tài khoản thử nghiệm:

- Username: `http_test`
- Password: `password123`

Thông tin tài khoản được lưu trong file mật khẩu Apache:

```text
/etc/apache2/.htpasswd
```

Kiểm tra khả năng truy cập tài nguyên khi chưa cung cấp thông tin xác thực:

```bash
curl -i http://192.168.190.130/secure/
```

Kết quả trả về:

```text
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="KB06 Protected Area"
```

Tiếp tục kiểm tra bằng tài khoản hợp lệ:

```bash
curl -i -u http_test http://192.168.190.130/secure/
```

Sau khi nhập mật khẩu, kết quả trả về:

```text
HTTP/1.1 200 OK
```

Nội dung phản hồi:

```html
<h1>KB06 - HTTP Basic Authentication</h1>
<p>Authentication successful!</p>
```

Kết quả xác nhận cơ chế HTTP Basic Authentication hoạt động đúng trước khi tiến hành kiểm thử.

### 4.4. Chuẩn bị Hydra và danh sách mật khẩu

Trên máy Attacker, sử dụng Hydra để mô phỏng hành vi thử nhiều mật khẩu đối với tài khoản HTTP Basic Authentication.

Danh sách mật khẩu thử nghiệm được lưu tại:

```text
/home/nhung/kb08_wordlist.txt
```

Danh sách gồm 10 mật khẩu thử nghiệm.

Kiểm tra số lượng dòng:

```bash
wc -l ~/kb08_wordlist.txt
```

Kết quả:

```text
10 /home/nhung/kb08_wordlist.txt
```

File lệnh tấn công được lưu tại:

```text
~/attack.sh
```

Nội dung lệnh kiểm thử:

```bash
#!/bin/bash

# KB06 - HTTP Basic Auth Brute Force

VICTIM="192.168.190.130"

hydra -l http_test -P /home/nhung/kb08_wordlist.txt -t 1 -w 2 "$VICTIM" http-get /secure/
```

Trong đó:

- `-l http_test`: Tài khoản được sử dụng để kiểm thử.
- `-P /home/nhung/kb08_wordlist.txt`: Đường dẫn đến danh sách mật khẩu.
- `-t 1`: Sử dụng một tác vụ đồng thời.
- `-w 2`: Thời gian chờ được thiết lập cho mỗi lần thử.
- `http-get`: Sử dụng phương thức HTTP GET để kiểm tra xác thực.
- `/secure/`: Đường dẫn tài nguyên được bảo vệ trên Victim.

### 4.5. Thực hiện kiểm thử HTTP Basic Auth Brute Force bằng Hydra

Trên máy Attacker, thực thi file lệnh:

```bash
chmod +x ~/attack.sh
~/attack.sh
```

Kết quả kiểm thử ghi nhận:

```text
[DATA] max 1 task per 1 server, overall 1 task, 10 login tries
[DATA] attacking http-get://192.168.190.130:80/secure/

[80][http-get] host: 192.168.190.130
login: http_test
password: password123

1 of 1 target successfully completed, 1 valid password found
```

Kết quả cho thấy Hydra đã thực hiện 10 lần thử và tìm được mật khẩu hợp lệ `password123`.

Tiếp tục kiểm tra bằng curl:

```bash
curl -i -u http_test:password123 http://192.168.190.130/secure/
```

Kết quả trả về `HTTP/1.1 200 OK`, xác nhận thông tin xác thực được Hydra tìm thấy là hợp lệ.

### 4.6. Kiểm thử Run 1 – Chỉ sử dụng bộ luật ET Open

Ở lần kiểm thử thứ nhất, tiến hành sử dụng bộ luật ET Open mà không nạp luật tự xây dựng `local.rules`.

Tạo file cấu hình riêng:

```bash
sudo cp /etc/suricata/suricata.yaml /tmp/kb08-run1.yaml
```

Tắt việc nạp `local.rules` trong cấu hình Run 1, giữ nguyên bộ luật ET Open.

Kiểm tra cấu hình:

```bash
sudo suricata -T -c /tmp/kb08-run1.yaml
```

Khởi chạy Suricata:

```bash
sudo suricata -c /tmp/kb08-run1.yaml -i ens37 -l /home/nhung/kb08-run1
```

Trong quá trình kiểm thử, lưu lại lưu lượng mạng bằng tcpdump:

```bash
sudo tcpdump -i ens37 -nn 'host 192.168.190.131 and tcp port 80' -w ~/kb08-run1/kb08-run1.pcap
```

Sau khi hoàn tất, kiểm tra số lượng cảnh báo:

```bash
sudo grep '"event_type":"alert"' ~/kb08-run1/eve.json | wc -l
```

Kiểm tra nhật ký:

```bash
sudo cat ~/kb08-run1/fast.log
```

Kết quả thực nghiệm ghi nhận:

| Trường thông tin | Giá trị |
|---|---|
| Tổng số alert | 1 |
| SID | 2011497 |
| Signature | ET SCAN Hydra User-Agent |
| Classification | Attempted Information Leak |
| Priority | 2 |

Nhận xét:

ET Open đã phát hiện dấu hiệu sử dụng Hydra thông qua User-Agent. Tuy nhiên, cảnh báo này chưa phải cảnh báo chuyên biệt phát hiện nhiều lần xác thực HTTP Basic Authentication thất bại.

### 4.7. Xây dựng luật phát hiện HTTP Basic Auth Brute Force trên Suricata

Trên máy Victim, bổ sung luật tự xây dựng vào file:

```text
/var/lib/suricata/rules/local.rules
```

Nội dung luật:

```text
alert http $HOME_NET any -> any any (msg:"LAB BRUTE HTTP basic auth many 401"; flow:established,from_server; http.stat_code; content:"401"; threshold:type both, track by_dst, count 5, seconds 60; classtype:attempted-admin; sid:1000014; rev:1;)
```

Giải thích luật:

- `alert http`: Tạo cảnh báo khi phát hiện lưu lượng HTTP phù hợp.
- `$HOME_NET any -> any any`: Theo dõi lưu lượng HTTP xuất phát từ mạng nội bộ được xác định trong cấu hình Suricata.
- `flow:established,from_server`: Chỉ kiểm tra dữ liệu từ phía máy chủ trong kết nối TCP đã thiết lập.
- `http.stat_code`: Kiểm tra mã trạng thái HTTP.
- `content:"401"`: Tìm mã trạng thái HTTP 401 Unauthorized.
- `threshold:type both`: Áp dụng cơ chế ngưỡng cảnh báo.
- `track by_dst`: Theo dõi theo địa chỉ IP đích.
- `count 5, seconds 60`: Ngưỡng thử nghiệm là 5 lần trong 60 giây.
- `classtype:attempted-admin`: Phân loại hành vi có dấu hiệu thử truy cập trái phép.
- `sid:1000014`: Mã định danh của luật.
- `rev:1`: Phiên bản luật.

Lưu ý: Ngưỡng 5 lần trong 60 giây là ngưỡng đã sử dụng trong thực nghiệm KB06. Ngưỡng chính thức cuối cùng vẫn cần được thống nhất với nhóm.

Kiểm tra cấu hình Suricata:

```bash
sudo suricata -T -c /tmp/kb08-run2.yaml
```

Kết quả:

```text
Configuration provided was successfully loaded. Exiting.
```

Cấu hình hợp lệ, trong đó bộ luật ET Open và `local.rules` đều được nạp.

### 4.8. Kiểm thử Run 2 – Bật luật tự xây dựng

Ở Run 2, tiến hành bật cả bộ luật ET Open và luật tự xây dựng SID `1000014`.

Tạo thư mục lưu kết quả:

```bash
mkdir -p ~/kb08-run2
```

Tạo file cấu hình riêng:

```bash
sudo cp /etc/suricata/suricata.yaml /tmp/kb08-run2.yaml
```

Kiểm tra danh sách rule được nạp:

```bash
grep -n -A 3 '^rule-files:' /tmp/kb08-run2.yaml
```

Kết quả xác nhận có cả:

```yaml
- suricata.rules
- local.rules
```

Khởi chạy Suricata:

```bash
sudo suricata -c /tmp/kb08-run2.yaml -i ens37 -l /home/nhung/kb08-run2
```

Đồng thời sử dụng tcpdump để lưu lại lưu lượng kiểm thử:

```bash
sudo tcpdump -i ens37 -nn 'host 192.168.190.131 and tcp port 80' -w ~/kb08-run2/kb08-run2.pcap
```

Sau khi Hydra hoàn tất, kiểm tra cảnh báo SID `1000014` trong `eve.json`:

```bash
sudo grep '"signature_id":1000014' ~/kb08-run2/eve.json
```

Kiểm tra trong `fast.log`:

```bash
sudo grep '1000014' ~/kb08-run2/fast.log
```

Kết quả ghi nhận:

| Trường thông tin | Giá trị |
|---|---|
| Tổng số alert | 2 |
| SID tự xây dựng | 1000014 |
| Signature | LAB BRUTE HTTP basic auth many 401 |
| Category | Attempted Administrator Privilege Gain |
| Severity | 1 |
| Source IP | 192.168.190.130 |
| Destination IP | 192.168.190.131 |
| Source port | 80 |
| Destination port | 47002 |
| HTTP method | GET |
| HTTP status | 401 |
| HTTP URL | /secure/ |
| User-Agent | Mozilla/4.0 (Hydra) |

Kết quả chứng minh luật tự xây dựng SID `1000014` đã phát hiện được các phản hồi HTTP 401 lặp lại trong quá trình kiểm thử và ghi nhận cảnh báo trong `eve.json` cũng như `fast.log`.

### 4.9. Đo độ trễ phát hiện

Tiến hành đối chiếu timestamp của cảnh báo trong `eve.json` với thời điểm phản hồi HTTP 401 thứ 5 trong PCAP.

Thời điểm ghi nhận:

| Sự kiện | Timestamp |
|---|---|
| Phản hồi HTTP 401 thứ 5 | 19:42:35.233521 |
| Thời điểm ghi nhận alert SID 1000014 | 19:42:35.335119 |

Độ trễ ước tính:

```text
19:42:35.335119 - 19:42:35.233521
= 0.101598 giây
≈ 0.102 giây
```

Kết quả cho thấy Suricata ghi nhận cảnh báo khoảng 0,102 giây sau phản hồi HTTP 401 thứ 5.

Đây là kết quả đo của một lượt thử nghiệm, chưa phải giá trị trung bình từ nhiều lần kiểm thử.

### 4.10. Kiểm tra cảnh báo sai bằng lưu lượng lành tính

Để đánh giá khả năng phát sinh cảnh báo sai, tiến hành tạo lưu lượng truy cập hợp lệ từ Attacker đến tài nguyên `/secure/`.

Sử dụng tài khoản hợp lệ:

- Username: `http_test`
- Password: `password123`

Thực hiện 10 request HTTP GET liên tiếp, mỗi request cách nhau 1 giây:

```bash
for i in $(seq 1 10); do curl -s -o /dev/null -w "Request $i: HTTP %{http_code}\n" -u http_test:password123 http://192.168.190.130/secure/; sleep 1; done
```

Kết quả:

```text
Request 1: HTTP 200
Request 2: HTTP 200
Request 3: HTTP 200
Request 4: HTTP 200
Request 5: HTTP 200
Request 6: HTTP 200
Request 7: HTTP 200
Request 8: HTTP 200
Request 9: HTTP 200
Request 10: HTTP 200
```

Lưu lại lưu lượng lành tính:

```bash
sudo tcpdump -i ens37 -nn 'host 192.168.190.131 and tcp port 80' -w ~/kb08-run2/kb08-benign.pcap
```

Kiểm tra số lượng cảnh báo SID `1000014`:

```bash
sudo grep '"signature_id":1000014' ~/kb08-run2/eve.json | wc -l
```

Kết quả sau khi kiểm tra:

- 10/10 request hợp lệ trả về HTTP 200.
- Không phát sinh thêm cảnh báo SID `1000014`.
- Tổng số alert SID `1000014` vẫn là 1, tương ứng với đợt kiểm thử Hydra trước đó.
- Có cảnh báo ET Open liên quan đến Curl trong `fast.log`, nhưng đây không phải cảnh báo của luật tự xây dựng SID `1000014`.

Nhận xét:

Trong phạm vi 10 request đăng nhập hợp lệ được kiểm thử, luật tự xây dựng không phát sinh thêm cảnh báo sai.

Tỷ lệ cảnh báo sai quan sát được đối với custom rule trong mẫu thử này là 0/10 request (0%). Kết quả chỉ phản ánh phạm vi thử nghiệm đã thực hiện, không đại diện cho mọi loại lưu lượng lành tính.

## 5. Tổng hợp kết quả thực nghiệm

| Nội dung đánh giá | Kết quả |
|---|---|
| Kết nối mạng Attacker – Victim | Thành công |
| Cài đặt và khởi động Apache | Thành công |
| Cấu hình HTTP Basic Authentication | Thành công |
| Kiểm tra HTTP 401 khi không có thông tin xác thực | Thành công |
| Kiểm tra đăng nhập hợp lệ HTTP 200 | Thành công |
| Hydra thực hiện kiểm thử | Thành công |
| Số mật khẩu thử nghiệm | 10 |
| Mật khẩu hợp lệ tìm được | password123 |
| Run 1 – ET Open | 1 alert |
| SID Run 1 | 2011497 |
| Run 1 phát hiện chuyên biệt HTTP Basic Auth Brute Force | Chưa |
| Run 2 – ET Open + Custom | 2 alert |
| SID luật tự xây dựng | 1000014 |
| Run 2 phát hiện bằng luật tự xây dựng | Có |
| Độ trễ phát hiện ước tính | 0,102 giây |
| Lưu lượng lành tính | 10 request HTTP 200 |
| Alert mới của custom rule trong thử nghiệm lành tính | 0 |
| Tỷ lệ False Positive quan sát được | 0/10 (0%) |

## 6. Kết luận

Nhiệm vụ KB06 đã hoàn thành các bước triển khai môi trường HTTP Basic Authentication, mô phỏng hành vi HTTP Basic Auth Brute Force bằng Hydra và xây dựng luật phát hiện trên Suricata.

Kết quả thực nghiệm cho thấy bộ luật ET Open đã phát hiện dấu hiệu sử dụng Hydra thông qua User-Agent nhưng chưa có cảnh báo chuyên biệt cho nhiều lần xác thực HTTP Basic Authentication thất bại.

Trong Run 2, luật tự xây dựng SID `1000014` đã phát hiện được các phản hồi HTTP 401 lặp lại trong quá trình kiểm thử. Cảnh báo được ghi nhận trong cả `eve.json` và `fast.log`.

Độ trễ phát hiện ước tính trong lượt thử nghiệm là khoảng 0,102 giây. Khi kiểm tra bằng 10 request đăng nhập hợp lệ, luật tự xây dựng không phát sinh thêm cảnh báo.

Như vậy, KB06 đã hoàn thành phần triển khai và kiểm thử kỹ thuật trong môi trường lab. Ngưỡng threshold cuối cùng vẫn cần được thống nhất với nhóm trước khi chốt cấu hình chính thức.


## Tệp nguồn và minh chứng gốc

Thư mục nguồn trong repository ban đầu: [`08-http-basic-auth-bruteforce`](https://github.com/phanyen206/Suricata/tree/main/scenarios/08-http-basic-auth-bruteforce). Các tệp nhị phân như PCAP, ảnh chụp, gói minh chứng hoặc tài liệu DOCX (nếu có) hiện vẫn được giữ tại repository nguồn; README này liên kết về nguồn để người đọc tải/xem, không thay thế bằng dữ liệu giả.
