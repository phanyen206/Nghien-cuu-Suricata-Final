> **Hướng dẫn người đọc:** README này mô tả mục tiêu, môi trường, thứ tự tái lập và cách kiểm tra kết quả. Hãy đọc phần môi trường và lệnh trước khi chạy script; cập nhật IP/interface theo lab của bạn. Chỉ chạy trong mạng ảo được phép.

# KB07 – TELNET BRUTE FORCE

## 1. Giới thiệu

Kịch bản KB07 mô phỏng hành vi dò đoán mật khẩu Telnet (Telnet Brute Force) trong mạng lab. Máy Attacker sử dụng Hydra và Expect để tạo các phiên đăng nhập thất bại đến máy Victim. Suricata giám sát lưu lượng TCP/23, đánh giá khả năng phát hiện của bộ luật ET Open và luật tự xây dựng SID 1000022.

- **MITRE ATT&CK:** T1110.001 – Password Guessing.
- **Công cụ kiểm thử:** THC Hydra, Expect.
- **Hệ thống giám sát:** Suricata 8.0.3 RELEASE.
- **Luật tự xây dựng:** SID 1000022 – LAB BRUTE TELNET multiple failed logins.

## 2. Môi trường thực nghiệm

| Thành phần | Thông tin |
|---|---|
| Attacker | 192.168.100.10/24 |
| Victim | 192.168.100.20/24 |
| Interface Victim | ens37 |
| Dịch vụ | Telnet – TCP/23 |
| Tài khoản thử nghiệm | telnet_test |

## 3. Các bước thực hiện

### Bước 1. Kiểm tra kết nối mạng

**Trên Attacker:**
```bash
ip -br -4 addr
ping -c 4 192.168.190.130
```

**Trên Victim:**
```bash
ip -br -4 addr
ping -c 4 192.168.190.131
```

**Kết quả:** Hai máy liên lạc hai chiều thành công, tỷ lệ mất gói 0% trong lượt kiểm tra.

### Bước 2. Kiểm tra dịch vụ Telnet

**Trên Victim:**
```bash
dpkg -l | grep -E 'inetutils-(telnetd|inetd)'
grep -n 'telnet stream' /etc/inetd.conf
sudo systemctl status inetutils-inetd --no-pager
sudo ss -lntp | grep ':23'
```

**Kết quả:** Dịch vụ Telnet đã được cài đặt, inetutils-inetd ở trạng thái active (running) và cổng TCP/23 đang LISTEN.

Kiểm tra tài khoản:
```bash
id telnet_test
```

**Trên Attacker**, kết nối thử:
```bash
telnet 192.168.190.130
```

Kiểm tra cả đăng nhập sai (nhận `Login incorrect`) và đăng nhập hợp lệ.

<img width="903" height="475" alt="image" src="https://github.com/user-attachments/assets/75d72e02-f775-4922-937d-5634376d4199" />

### Bước 3. Chuẩn bị công cụ và thực hiện kiểm thử

**Trên Attacker:**
```bash
hydra -h | head -n 5
wc -l ~/kb09-passwords.txt
ls -lh ~/kb09-passwords.txt
```

Thực hiện kiểm thử bằng Hydra:
```bash
hydra -l telnet_test -P ~/kb09-passwords.txt telnet://192.168.190.130 -t 1 -W 5 -V -d
```

Do kết quả xác thực Telnet của Hydra không ổn định, sử dụng thêm Expect để tạo 5 phiên đăng nhập thất bại:
```bash
ls -lh ~/kb09-test5.exp
expect ~/kb09-test5.exp
```

**Kết quả:** Expect tạo 5 phiên đăng nhập thất bại riêng biệt, mỗi phiên nhận phản hồi `Login incorrect`. Không khẳng định Hydra tìm được mật khẩu hợp lệ nếu đầu ra thực tế không chứng minh điều đó.

<img width="852" height="58" alt="image" src="https://github.com/user-attachments/assets/167b70cd-330a-41c9-bd1c-74ac262abe18" />

<img width="539" height="707" alt="image" src="https://github.com/user-attachments/assets/2b058e4b-268c-416f-b138-4bcf9a22a1ff" />

<img width="559" height="682" alt="image" src="https://github.com/user-attachments/assets/9e23d9a1-e5af-42ca-be25-5ba13a14ad74" />


### Bước 4. Kiểm tra cấu hình Suricata và luật tự xây dựng

**Trên Victim:**
```bash
sudo grep -n -A 8 'HOME_NET:' /etc/suricata/suricata.yaml
sudo grep -n -A 3 '^rule-files:' /etc/suricata/suricata.yaml
sudo grep -n -A 2 'af-packet:' /etc/suricata/suricata.yaml
sudo suricata -T -c /etc/suricata/suricata.yaml
```

Kiểm tra luật:
```bash
sudo grep -n 'LAB BRUTE TELNET' /var/lib/suricata/rules/local.rules
```

**Luật SID 1000022 đã xác minh trong tài liệu:**
```text
alert tcp $HOME_NET 23 -> any any (msg:"LAB BRUTE TELNET multiple failed logins"; flow:established; content:"Login incorrect"; nocase; detection_filter:track by_dst, count 4, seconds 60; classtype:attempted-admin; sid:1000022; rev:7;)
```

**Kết quả:** HOME_NET là `192.168.190.130`, interface giám sát `ens37`; hai file luật `suricata.rules` và `local.rules` được khai báo. Cấu hình Suricata kiểm tra nạp thành công.

<img width="609" height="226" alt="image" src="https://github.com/user-attachments/assets/14b341cd-9ca8-4f4e-97fe-c0ffcfce833b" />

<img width="602" height="78" alt="image" src="https://github.com/user-attachments/assets/3ed5ee8d-32e0-4fca-84f4-f8e1eda5e76d" />

<img width="598" height="58" alt="image" src="https://github.com/user-attachments/assets/ea7ec60b-f7ae-4a1b-b12f-f6286c90fed1" />

<img width="607" height="34" alt="image" src="https://github.com/user-attachments/assets/cdd22712-8808-40ea-b540-bd31b2d977c2" />

<img width="609" height="92" alt="image" src="https://github.com/user-attachments/assets/46479873-5028-4d66-afdf-5a94bf91d06a" />

### Bước 5. Run 1 – Sử dụng ET Open

Sao chép cấu hình và tắt `local.rules`:
```bash
sudo cp /etc/suricata/suricata.yaml /tmp/kb09-run1.yaml
sudo sed -i '/^[[:space:]]*-[[:space:]]*local\.rules[[:space:]]*$/s/^/#/' /tmp/kb09-run1.yaml
grep -n -A 3 '^rule-files:' /tmp/kb09-run1.yaml
sudo suricata -T -c /tmp/kb09-run1.yaml
```

**Trên Victim – Terminal 1**, chạy Suricata:
```bash
sudo systemctl stop suricata
sudo systemctl is-active suricata
sudo suricata -c /tmp/kb09-run1.yaml -i ens37 -l /home/nhung/kb09-run1
```

**Trên Victim – Terminal 2**, bắt lưu lượng:
```bash
sudo tcpdump -i ens37 -nn 'host 192.168.190.131 and tcp port 23' -w ~/kb09-run1/kb09-run1.pcap
```

**Trên Attacker**, chạy lại kịch bản kiểm thử:
```bash
hydra -l telnet_test -P ~/kb09-passwords.txt telnet://192.168.190.130 -t 1 -W 5 -V -d
```

Nếu cần tạo 5 phiên thất bại có thể kiểm chứng, sử dụng script Expect tương ứng. Sau khi hoàn tất, nhấn `Ctrl+C` để dừng tcpdump và tiến trình Suricata.

Kiểm tra kết quả:
```bash
grep -ac '"event_type":"alert"' ~/kb09-run1/eve.json
grep -a '"event_type":"alert"' ~/kb09-run1/eve.json | grep -o '"signature_id":[0-9]*' | sort | uniq -c
cat ~/kb09-run1/fast.log
sudo tcpdump -nn -A -r ~/kb09-run1/kb09-run1.pcap 'tcp port 23' 2>/dev/null | grep -ic 'Login incorrect'
```

**Kết quả Run 1:**
- Tổng cộng 17 alert.
- SID 2068415: 5 lần.
- SID 2101251: 6 lần – GPL TELNET Bad Login.
- SID 2221010: 6 lần.
- PCAP ghi nhận 5 phản hồi `Login incorrect`.

ET Open đã phát hiện dấu hiệu đăng nhập Telnet thất bại, đặc biệt qua SID 2101251.

<img width="609" height="66" alt="image" src="https://github.com/user-attachments/assets/f6abffc5-8b1e-4a4a-ae99-f4457751ebcc" />

<img width="608" height="346" alt="image" src="https://github.com/user-attachments/assets/3c06123c-ecc3-4553-8049-940b8ae866b5" />

### Bước 6. Run 2 – Bật luật tự xây dựng

Kiểm tra luật và cấu hình:
```bash
sudo grep -n -A 3 '^rule-files:' /etc/suricata/suricata.yaml
sudo grep -n 'LAB BRUTE TELNET' /var/lib/suricata/rules/local.rules
```

Phân tích offline PCAP Run 2 bằng cấu hình có cả ET Open và local.rules:
```bash
mkdir -p ~/kb09-run2-custom/replay2

sudo suricata -r ~/kb09-run2-custom/kb09-run2-custom.pcap \
-c /etc/suricata/suricata.yaml \
-l ~/kb09-run2-custom/replay2
```

Kiểm tra cảnh báo:
```bash
sudo grep -ac '"signature_id":1000022' ~/kb09-run2-custom/replay2/eve.json
sudo grep -a 'LAB BRUTE TELNET' ~/kb09-run2-custom/replay2/fast.log
```

**Kết quả Run 2:**
- PCAP ghi nhận 5 phản hồi `Login incorrect`.
- Suricata đọc 185 packets.
- Ghi nhận 2 alert theo SID 1000022 trong `eve.json`.
- `fast.log` xác nhận 2 dòng cảnh báo của luật tự xây dựng.

Lưu ý: Hai alert có cùng timestamp và cùng luồng TCP, không được xem là hai đợt tấn công riêng biệt. Run 1 và Run 2 sử dụng hai PCAP khác nhau nên không thể coi đây là phép so sánh trực tiếp trên cùng một dữ liệu.

<img width="600" height="226" alt="image" src="https://github.com/user-attachments/assets/15b9c97e-b7f0-4248-bc86-77489d3ccbeb" />

### Bước 7. Kiểm tra lưu lượng lành tính (Benign)

**Trên Attacker:** Thực hiện một phiên đăng nhập Telnet hợp lệ:
```bash
telnet 192.168.190.130
```

Nhập tài khoản `telnet_test` cùng mật khẩu hợp lệ, sau đó thoát bằng `exit`.

**Trên Victim:** Kiểm tra kết quả:
```bash
ls -lh ~/kb09-run2-custom/benign/
grep -ac '"signature_id":1000022' ~/kb09-run2-custom/benign/eve.json
cat ~/kb09-run2-custom/benign/fast.log
```

**Kết quả:**
- Không ghi nhận alert SID 1000022.
- ET Open vẫn ghi nhận một cảnh báo SID 2068415.
- Luật tự xây dựng không kích hoạt trong phiên đăng nhập hợp lệ được kiểm tra.

Lưu ý: Benign mới được kiểm tra trên một phiên đăng nhập hợp lệ, chưa đủ cơ sở để kết luận tỷ lệ false positive bằng 0 trong mọi tình huống.

<img width="579" height="470" alt="image" src="https://github.com/user-attachments/assets/65c58333-1442-4644-a17f-25d878712f04" />

<img width="611" height="102" alt="image" src="https://github.com/user-attachments/assets/6e241dab-a66d-4e75-9522-b649634c355d" />

### Bước 8. Lưu trữ dữ liệu và kiểm tra kết quả

```bash
ls -lh ~/KB09/Run1_ET_Open/
ls -lh ~/KB09/Run2_Custom/
ls -lh ~/KB09/Benign/
grep -n 'LAB BRUTE TELNET' ~/KB09/Rules/local.rules
find ~/KB09 -maxdepth 3 -type f -printf '%P (%k KB)\n' | sort
```

Dữ liệu cần lưu gồm:
- PCAP của Run 1 và Run 2.
- `eve.json`, `fast.log`, `stats.log`, `suricata.log`.
- File `local.rules` chứa SID 1000022.
- Dữ liệu kiểm thử Benign.

<img width="546" height="347" alt="image" src="https://github.com/user-attachments/assets/0e2c447c-9570-48b5-a229-51b82fca6985" />
  
<img width="600" height="248" alt="image" src="https://github.com/user-attachments/assets/f1d62c1c-5cf9-4957-a911-1aed69e38838" />

## 4. Tổng hợp kết quả

| Nội dung | Kết quả |
|---|---|
| Kết nối mạng | Ping hai chiều thành công |
| Dịch vụ Telnet | inetutils-inetd active; TCP/23 LISTEN |
| Hydra | Đã thực hiện; kết quả xác thực không ổn định |
| Expect | 5 phiên đăng nhập thất bại |
| PCAP Run 1 | 5 phản hồi `Login incorrect` |
| Run 1 – ET Open | 17 alert |
| Run 2 – Custom rule | 2 alert SID 1000022 |
| Benign | 1 phiên hợp lệ; 0 alert SID 1000022 |
| Latency | Chưa xác định chính xác |

## 5. Kết luận

Kịch bản KB07 đã triển khai thành công dịch vụ Telnet trên máy Victim, tạo các phiên đăng nhập thất bại và thu thập lưu lượng TCP/23 để phân tích bằng Suricata.

Trong Run 1, ET Open ghi nhận 17 alert, trong đó SID 2101251 – GPL TELNET Bad Login phản ánh trực tiếp các lần đăng nhập Telnet thất bại. Ở Run 2, luật tự xây dựng SID 1000022 được kích hoạt với 2 alert khi phân tích PCAP có 5 phản hồi `Login incorrect`.

Trong thử nghiệm Benign, luật SID 1000022 không phát cảnh báo đối với phiên đăng nhập hợp lệ đã kiểm tra, mặc dù ET Open vẫn ghi nhận một cảnh báo riêng. Kết quả cho thấy luật tự xây dựng có khả năng nhận diện các lần đăng nhập thất bại lặp lại theo điều kiện đã thiết lập và không kích hoạt trong mẫu đăng nhập hợp lệ được thử nghiệm.

Một số giới hạn cần lưu ý: Hydra không có kết quả xác thực ổn định; Expect được sử dụng bổ sung để tạo các phiên thất bại có thể kiểm chứng. Độ trễ phát hiện chưa xác định chính xác và dữ liệu Benign mới chỉ gồm một phiên đăng nhập hợp lệ. Ngoài ra, Run 1 và Run 2 sử dụng hai PCAP riêng biệt nên chưa đủ cơ sở để so sánh định lượng trực tiếp hiệu quả của hai cấu hình trên cùng dữ liệu.

## Tệp nguồn và minh chứng gốc

Thư mục nguồn trong repository ban đầu: [`09-telnet-bruteforce`](https://github.com/phanyen206/Suricata/tree/main/scenarios/09-telnet-bruteforce). Các tệp nhị phân như PCAP, ảnh chụp, gói minh chứng hoặc tài liệu DOCX (nếu có) hiện vẫn được giữ tại repository nguồn; README này liên kết về nguồn để người đọc tải/xem, không thay thế bằng dữ liệu giả.
