> **Hướng dẫn người đọc:** README này mô tả mục tiêu, môi trường, thứ tự tái lập và cách kiểm tra kết quả. Hãy đọc phần môi trường và lệnh trước khi chạy script; cập nhật IP/interface theo lab của bạn. Chỉ chạy trong mạng ảo được phép.

# KB07 – TELNET BRUTE FORCE

## 1. Thông tin nhiệm vụ

- **Người phụ trách:** Uyên
- **Tên kịch bản:** KB07 – Telnet Brute Force
- **Nhóm tấn công:** Mật khẩu (Password)
- **MITRE ATT&CK:** T1110.001 – Password Guessing
- **Công cụ kiểm thử:** THC Hydra, Expect, Telnet
- **Công cụ giám sát và phát hiện:** Suricata 8.0.3 RELEASE
- **SID luật tự xây dựng:** 1000022

## 2. Mục tiêu thực hiện

Nhiệm vụ KB07 nhằm mô phỏng hành vi tấn công vét cạn mật khẩu thông qua giao thức Telnet trên máy Victim, từ đó đánh giá khả năng phát hiện của hệ thống Suricata.

Các mục tiêu cụ thể:

- Thiết lập kết nối mạng giữa máy Attacker và Victim.
- Cài đặt và cấu hình dịch vụ Telnet trên Victim.
- Tạo tài khoản thử nghiệm và kiểm tra khả năng đăng nhập.
- Sử dụng Hydra để mô phỏng hành vi thử nhiều mật khẩu.
- Xây dựng luật Suricata nhằm phát hiện nhiều lần đăng nhập Telnet thất bại.
- Đánh giá khả năng phát hiện của bộ luật ET Open và luật tự xây dựng.
- Kiểm tra cảnh báo trong nhật ký `eve.json` và `fast.log`.
- Kiểm tra hoạt động của luật với lưu lượng đăng nhập hợp lệ nhằm đánh giá false positive.
- Thu thập PCAP và log phục vụ phân tích kết quả.

## 3. Môi trường thực nghiệm

Mô hình thực nghiệm sử dụng hai máy ảo Ubuntu được kết nối thông qua mạng LAN Segment trên VMware.

| Thành phần | Thông tin |
|---|---|
| Máy Attacker | Ubuntu |
| Địa chỉ IP Attacker | 192.168.190.131 |
| Máy Victim | Ubuntu |
| Địa chỉ IP Victim | 192.168.190.130 |
| Giao thức kiểm thử | Telnet/TCP |
| Cổng dịch vụ | 23 |
| Công cụ tấn công mô phỏng | THC Hydra |
| Công cụ tự động hóa kiểm thử | Expect |
| Công cụ phát hiện | Suricata 8.0.3 RELEASE |
| Dịch vụ Telnet | inetutils-telnetd |
| Tài khoản thử nghiệm | telnet_test |
| Giao diện mạng Victim | ens37 |

## 4. Các bước triển khai thực nghiệm

### 4.1. Kiểm tra kết nối mạng giữa Attacker và Victim

Sau khi khởi động hai máy ảo, tiến hành kiểm tra địa chỉ IP và khả năng kết nối mạng.

Địa chỉ IP thực tế được sử dụng:

- Attacker: `192.168.190.131`
- Victim: `192.168.190.130`

Kết quả kiểm tra cho thấy hai máy có thể liên lạc với nhau thông qua mạng lab. Các lần kiểm tra ping được ghi nhận đều thành công, không có gói tin bị mất.

### 4.2. Cài đặt và cấu hình dịch vụ Telnet trên Victim

Trên máy Victim, tiến hành cài đặt dịch vụ Telnet bằng các gói `inetutils-telnetd` và `inetutils-inetd`.

Bật dịch vụ Telnet:

```bash
sudo update-inetd --enable telnet
```

Khởi động lại dịch vụ:

```bash
sudo systemctl restart inetutils-inetd
```

Kiểm tra trạng thái dịch vụ:

```bash
sudo systemctl status inetutils-inetd
```

Kiểm tra cổng Telnet:

```bash
sudo ss -lntp | grep ':23'
```

Kết quả xác nhận dịch vụ Telnet hoạt động và lắng nghe trên cổng TCP/23.

### 4.3. Tạo tài khoản thử nghiệm và kiểm tra đăng nhập

Tạo tài khoản thử nghiệm trên máy Victim:

- Username: `telnet_test`
- Password: Mật khẩu thử nghiệm được thiết lập riêng trong môi trường lab.

Tiến hành kiểm tra từ máy Attacker:

```bash
telnet 192.168.190.130
```

Nhập thông tin tài khoản thử nghiệm.

Kết quả kiểm tra ghi nhận:

- Khi nhập sai mật khẩu, máy Victim trả về `Login incorrect`.
- Khi nhập đúng thông tin xác thực, người dùng đăng nhập thành công và nhận được shell của hệ thống.

Kết quả xác nhận dịch vụ Telnet hoạt động bình thường trước khi tiến hành kiểm thử.

### 4.4. Chuẩn bị Hydra và danh sách mật khẩu

Trên máy Attacker, sử dụng THC Hydra để mô phỏng hành vi thử nhiều mật khẩu đối với tài khoản Telnet.

Danh sách mật khẩu thử nghiệm được lưu tại:

```text
/home/nhung/kb09-passwords.txt
```

Tạo danh sách một mật khẩu sai phục vụ kiểm thử nhiều phiên kết nối riêng biệt:

```bash
head -n 1 ~/kb09-passwords.txt > ~/kb09-one-wrong.txt
```

Kiểm tra số lượng dòng:

```bash
wc -l ~/kb09-one-wrong.txt
```

Kết quả ghi nhận danh sách kiểm thử riêng có 1 dòng.

Lệnh Hydra được sử dụng:

```bash
hydra -l telnet_test -P ~/kb09-passwords.txt telnet://192.168.190.130 -t 1 -W 5 -V -d
```

Trong đó:

- `-l telnet_test`: Tài khoản được sử dụng để kiểm thử.
- `-P`: Đường dẫn đến danh sách mật khẩu.
- `-t 1`: Sử dụng một tác vụ đồng thời.
- `-W 5`: Thời gian chờ thiết lập kết nối.
- `-V`: Hiển thị chi tiết từng lần thử.
- `-d`: Bật chế độ debug.
- `telnet://192.168.190.130`: Máy Victim cung cấp dịch vụ Telnet.

Trong quá trình thử nghiệm, Hydra có một số lần không phân tích ổn định phản hồi Telnet. Vì vậy, nhóm sử dụng thêm Expect để tự động hóa các phiên đăng nhập sai riêng biệt, bảo đảm dữ liệu PCAP có thể ghi nhận các phản hồi `Login incorrect`.

### 4.5. Tự động hóa các phiên đăng nhập sai bằng Expect

Cài đặt Expect trên máy Attacker:

```bash
sudo apt install -y expect
```

Kiểm tra phiên bản:

```bash
expect -v
```

Kết quả ghi nhận Expect phiên bản `5.45.4`.

Tạo script:

```text
~/kb09-test5.exp
```

Script thực hiện 5 phiên Telnet riêng biệt. Trong mỗi phiên, chương trình gửi username `telnet_test`, nhập mật khẩu sai, kiểm tra phản hồi `Login incorrect`, sau đó đóng kết nối và chuyển sang phiên tiếp theo.

Kết quả thực nghiệm:

- Lần 1: Đăng nhập thất bại.
- Lần 2: Đăng nhập thất bại.
- Lần 3: Đăng nhập thất bại.
- Lần 4: Đăng nhập thất bại.
- Lần 5: Đăng nhập thất bại.

Cả 5 phiên đều nhận được phản hồi `Login incorrect`.

### 4.6. Kiểm thử Run 1 – Chỉ sử dụng bộ luật ET Open

Ở lần kiểm thử thứ nhất, tiến hành sử dụng bộ luật ET Open mà không nạp luật tự xây dựng `local.rules`.

Tạo thư mục lưu kết quả:

```bash
mkdir -p ~/kb09-run1
```

Tạo file cấu hình riêng:

```bash
sudo cp /etc/suricata/suricata.yaml /tmp/kb09-run1.yaml
```

Tắt việc nạp `local.rules` trong cấu hình Run 1, giữ nguyên bộ luật ET Open.

Kiểm tra cấu hình:

```bash
sudo suricata -T -c /tmp/kb09-run1.yaml
```

Khởi chạy Suricata:

```bash
sudo suricata -c /tmp/kb09-run1.yaml -i ens37 -l /home/nhung/kb09-run1
```

Trong quá trình kiểm thử, lưu lại lưu lượng mạng bằng tcpdump:

```bash
sudo tcpdump -i ens37 -nn 'host 192.168.190.131 and tcp port 23' -w ~/kb09-run1/kb09-run1.pcap
```

Sau khi hoàn tất, kiểm tra số lượng cảnh báo:

```bash
sudo grep -ac '"event_type":"alert"' ~/kb09-run1/eve.json
```

Kiểm tra nhật ký:

```bash
sudo cat ~/kb09-run1/fast.log
```

Kết quả thực nghiệm ghi nhận:

| Trường thông tin | Giá trị |
|---|---|
| Tổng số alert | 6 |
| SID 2101251 | 1 |
| SID 2221010 | 5 |
| Cảnh báo liên quan Telnet | GPL TELNET Bad Login |
| Cảnh báo khác | SURICATA HTTP unable to match response to request |

Nhận xét:

ET Open đã phát hiện hành vi đăng nhập Telnet thất bại thông qua SID `2101251` – `GPL TELNET Bad Login`.

Tuy nhiên, trong tổng số 6 alert, chỉ có 1 alert liên quan trực tiếp đến đăng nhập Telnet thất bại. Các alert còn lại thuộc SID `2221010`, không phải cảnh báo chuyên biệt cho hành vi Telnet Brute Force.

### 4.7. Xây dựng luật phát hiện Telnet Brute Force trên Suricata

Trên máy Victim, bổ sung luật tự xây dựng vào file:

```text
/var/lib/suricata/rules/local.rules
```

Nội dung luật cuối cùng:

```text
alert tcp $HOME_NET 23 -> any any (msg:"LAB BRUTE TELNET multiple failed logins"; flow:established; content:"Login incorrect"; nocase; detection_filter:track by_dst, count 4, seconds 60; classtype:attempted-admin; sid:1000022; rev:7;)
```

Giải thích luật:

- `alert tcp`: Tạo cảnh báo khi phát hiện lưu lượng TCP phù hợp.
- `$HOME_NET 23 -> any any`: Theo dõi lưu lượng xuất phát từ cổng Telnet 23 của mạng nội bộ.
- `flow:established`: Chỉ kiểm tra kết nối TCP đã được thiết lập.
- `content:"Login incorrect"`: Tìm chuỗi phản hồi thể hiện đăng nhập thất bại.
- `nocase`: Không phân biệt chữ hoa và chữ thường.
- `detection_filter`: Áp dụng cơ chế lọc theo số lần xuất hiện.
- `track by_dst`: Theo dõi theo địa chỉ IP đích.
- `count 4, seconds 60`: Cấu hình ngưỡng thử nghiệm trong khoảng thời gian 60 giây. Trong lần kiểm thử thực tế, luật đã phát cảnh báo khi ghi nhận 5 lần đăng nhập sai.
- `classtype:attempted-admin`: Phân loại hành vi có dấu hiệu thử truy cập trái phép.
- `sid:1000022`: Mã định danh của luật.
- `rev:7`: Phiên bản luật.

Kiểm tra cấu hình Suricata:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

Kết quả:

```text
Configuration provided was successfully loaded. Exiting.
```

Kết quả xác nhận cấu hình hợp lệ, trong đó cả bộ luật ET Open và `local.rules` đều được nạp.

### 4.8. Kiểm thử Run 2 – Bật luật tự xây dựng

Ở Run 2, tiến hành bật cả bộ luật ET Open và luật tự xây dựng SID `1000022`.

Tạo thư mục lưu kết quả:

```bash
mkdir -p ~/kb09-run2-custom
```

Khởi chạy Suricata với cấu hình đầy đủ:

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i ens37 -l /home/nhung/kb09-run2-custom
```

Đồng thời sử dụng tcpdump để lưu lại lưu lượng kiểm thử:

```bash
sudo tcpdump -i ens37 -nn 'host 192.168.190.131 and tcp port 23' -w ~/kb09-run2-custom/kb09-run2-custom.pcap
```

Thực hiện 5 phiên Telnet riêng biệt bằng script Expect đã chuẩn bị ở mục 4.5.

Sau khi hoàn tất, kiểm tra PCAP:

```bash
sudo tcpdump -nn -A -r ~/kb09-run2-custom/kb09-run2-custom.pcap 'tcp port 23' 2>/dev/null | grep -ic 'Login incorrect'
```

Kết quả:

```text
5
```

Tiến hành phân tích lại PCAP bằng Suricata:

```bash
mkdir -p ~/kb09-run2-custom/replay2

sudo suricata -r ~/kb09-run2-custom/kb09-run2-custom.pcap -c /etc/suricata/suricata.yaml -l ~/kb09-run2-custom/replay2
```

Kiểm tra cảnh báo SID `1000022` trong `eve.json`:

```bash
sudo grep -ac '"signature_id":1000022' ~/kb09-run2-custom/replay2/eve.json
```

Kết quả ghi nhận:

```text
1
```

Thông tin alert:

| Trường thông tin | Giá trị |
|---|---|
| SID | 1000022 |
| Revision | 7 |
| Signature | LAB BRUTE TELNET multiple failed logins |
| Category | Attempted Administrator Privilege Gain |
| Severity | 1 |
| Protocol | TCP |
| Source IP | 192.168.190.130 |
| Source port | 23 |
| Destination IP | 192.168.190.131 |
| Destination port | 47480 |

Kết quả chứng minh luật tự xây dựng SID `1000022` đã phát hiện được hành vi đăng nhập Telnet thất bại trong lần kiểm thử có 5 phiên đăng nhập sai.

### 4.9. Đo độ trễ phát hiện

Tiến hành đối chiếu timestamp của cảnh báo trong `eve.json` với thời điểm phản hồi `Login incorrect` thứ 5 trong PCAP.

Kết quả ghi nhận 5 timestamp phản hồi:

| Lần | Timestamp Unix |
|---|---|
| 1 | 1793559873.225041 |
| 2 | 1793559875.884384 |
| 3 | 1793559879.217908 |
| 4 | 1793559879.476819 |
| 5 | 1793559885.682400 |

Timestamp alert trong `eve.json`:

```text
2026-11-02T02:04:30.880550+0700
```

Do timestamp alert và timestamp phản hồi trong PCAP không khớp thứ tự thời gian, chưa thể xác định chính xác độ trễ phát hiện từ dữ liệu hiện có.

Vì vậy, độ trễ phát hiện được ghi nhận là **chưa xác định chính xác**, cần kiểm tra lại cách đồng bộ và ghi nhận timestamp trước khi thực hiện phép đo chính thức.

### 4.10. Kiểm tra cảnh báo sai bằng lưu lượng lành tính

Để đánh giá khả năng phát sinh cảnh báo sai, tiến hành tạo một phiên đăng nhập Telnet hợp lệ từ Attacker đến Victim.

Sử dụng tài khoản thử nghiệm:

- Username: `telnet_test`
- Password: Mật khẩu hợp lệ đã thiết lập trên Victim.

Thực hiện kết nối:

```bash
telnet 192.168.190.130
```

Nhập thông tin xác thực hợp lệ và kiểm tra khả năng đăng nhập.

Kết quả ghi nhận người dùng đăng nhập thành công, nhận được shell của hệ thống và thoát phiên Telnet bình thường.

Kiểm tra số lượng cảnh báo SID `1000022`:

```bash
sudo grep -ac '"signature_id":1000022' ~/kb09-run2-custom/benign/eve.json
```

Kết quả:

```text
0
```

Nhận xét:

- Đăng nhập Telnet hợp lệ thành công.
- Không phát sinh cảnh báo mới từ luật tự xây dựng SID `1000022`.
- Số lượng false positive quan sát được trong lần thử nghiệm này là 0.

Kết quả chỉ phản ánh một lần đăng nhập hợp lệ được kiểm tra, chưa đại diện cho mọi loại lưu lượng lành tính.

## 5. Tổng hợp kết quả thực nghiệm

| Nội dung đánh giá | Kết quả |
|---|---|
| Kết nối mạng Attacker – Victim | Thành công |
| Cài đặt và khởi động dịch vụ Telnet | Thành công |
| Kiểm tra đăng nhập Telnet hợp lệ | Thành công |
| Kiểm tra phản hồi đăng nhập sai | Thành công |
| Hydra thực hiện kiểm thử | Đã thử nghiệm, có hạn chế tương thích |
| Expect tự động hóa 5 phiên Telnet | Thành công |
| Số lần đăng nhập sai trong Run 2 | 5 |
| Run 1 – Tổng số alert ET Open | 6 |
| Run 1 – SID GPL TELNET Bad Login | 2101251 (1 alert) |
| Run 2 – Custom alert | 1 |
| SID luật tự xây dựng | 1000022 |
| Revision luật | 7 |
| Benign traffic | 1 lần đăng nhập hợp lệ |
| Alert custom trong benign traffic | 0 |
| False Positive quan sát được | 0 |
| Độ trễ phát hiện | Chưa xác định chính xác |

## 6. Kết luận

Nhiệm vụ KB07 đã hoàn thành các bước triển khai môi trường Telnet, mô phỏng hành vi đăng nhập sai nhiều lần và xây dựng luật phát hiện trên Suricata.

Kết quả thực nghiệm cho thấy bộ luật ET Open đã phát hiện hành vi đăng nhập Telnet thất bại thông qua SID `2101251` – `GPL TELNET Bad Login`.

Trong Run 2, luật tự xây dựng SID `1000022` đã phát hiện được hành vi đăng nhập Telnet thất bại sau khi kiểm thử 5 phiên kết nối riêng biệt. Cảnh báo được ghi nhận trong `eve.json`.

Khi kiểm tra bằng một phiên đăng nhập hợp lệ, luật tự xây dựng không phát sinh cảnh báo sai.

Tuy nhiên, độ trễ phát hiện chưa thể xác định chính xác do timestamp giữa PCAP và EVE chưa khớp. Đây là hạn chế cần được kiểm tra bổ sung nếu yêu cầu đánh giá latency chính thức.

Như vậy, KB07 đã hoàn thành phần triển khai và kiểm thử phát hiện cơ bản trong môi trường lab, đồng thời đã lưu trữ PCAP, log và luật tự xây dựng để phục vụ việc kiểm tra, đánh giá và báo cáo.


## Tệp nguồn và minh chứng gốc

Thư mục nguồn trong repository ban đầu: [`09-telnet-bruteforce`](https://github.com/phanyen206/Suricata/tree/main/scenarios/09-telnet-bruteforce). Các tệp nhị phân như PCAP, ảnh chụp, gói minh chứng hoặc tài liệu DOCX (nếu có) hiện vẫn được giữ tại repository nguồn; README này liên kết về nguồn để người đọc tải/xem, không thay thế bằng dữ liệu giả.
