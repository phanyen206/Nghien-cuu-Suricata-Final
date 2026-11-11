> **Hướng dẫn người đọc:** README này mô tả mục tiêu, môi trường, thứ tự tái lập và cách kiểm tra kết quả. Hãy đọc phần môi trường và lệnh trước khi chạy script; cập nhật IP/interface theo lab của bạn. Chỉ chạy trong mạng ảo được phép.

# BÁO CÁO KẾT QUẢ THỰC HIỆN NHIỆM VỤ KB04
## Kiểm thử SSH Brute Force và cấu hình Suricata phát hiện

### 1. Thông tin nhiệm vụ

- **Người thực hiện:** Uyên
- **Tên kịch bản:** KB04 – SSH Brute Force
- **Nhóm tấn công:** Mật khẩu (Password)
- **MITRE ATT&CK:** T1110.001 – Password Guessing
- **Công cụ kiểm thử:** THC Hydra
- **Công cụ giám sát và phát hiện:** Suricata
- **SID luật tự xây dựng:** 1000004

### 2. Mục tiêu thực hiện

Nhiệm vụ KB04 nhằm mô phỏng hành vi thử nhiều mật khẩu để đăng nhập vào dịch vụ SSH trên máy Victim, từ đó kiểm tra khả năng phát hiện của hệ thống Suricata.

Các mục tiêu cụ thể:

- Thiết lập kết nối mạng giữa máy Attacker và Victim.
- Cài đặt và kiểm tra hoạt động của dịch vụ SSH trên Victim.
- Tạo tài khoản thử nghiệm phục vụ quá trình kiểm thử.
- Sử dụng Hydra để mô phỏng hành vi đoán mật khẩu SSH trong môi trường lab.
- Xây dựng và kiểm tra luật Suricata nhằm phát hiện các kết nối SSH lặp lại từ cùng một địa chỉ IP.
- Kiểm tra cảnh báo được ghi nhận trong nhật ký `eve.json`.

### 3. Môi trường thực nghiệm

Mô hình thực nghiệm sử dụng hai máy ảo Ubuntu được kết nối thông qua mạng LAN Segment trên VMware.

| Thành phần | Thông tin |
|---|---|
| Máy Attacker | Ubuntu |
| Địa chỉ IP Attacker | 192.168.100.10 |
| Máy Victim | Ubuntu 26.04.1 LTS |
| Địa chỉ IP Victim | 192.168.100.20 |
| Giao thức kiểm thử | SSH/TCP |
| Cổng dịch vụ | 22 |
| Công cụ tấn công mô phỏng | Hydra 9.6 |
| Công cụ phát hiện | Suricata 8.0.3 RELEASE |

**Kiểm tra kết nối mạng**

Sau khi cấu hình địa chỉ IP cho hai máy, tiến hành sử dụng lệnh `ping` để kiểm tra khả năng liên lạc giữa Attacker và Victim.

Kết quả cho thấy hai máy có thể gửi và nhận gói tin ICMP thành công, không có gói tin bị mất trong các lần kiểm tra được ghi nhận.

<img width="940" height="425" alt="image" src="https://github.com/user-attachments/assets/8014e57d-5897-4fd3-a891-85adbefe3bd9" />

<img width="940" height="530" alt="image" src="https://github.com/user-attachments/assets/cafeeb0e-a6a5-499c-82c6-9a39b27c6069" />

### 4. Các bước triển khai thực nghiệm

#### 4.1. Kiểm tra dịch vụ SSH trên Victim

Trên máy Victim, tiến hành kiểm tra trạng thái dịch vụ SSH bằng lệnh:

```bash
sudo systemctl status ssh
```

Kết quả cho thấy dịch vụ SSH đang hoạt động với trạng thái `active (running)`.

Tiếp theo, kiểm tra cổng 22 đang lắng nghe bằng lệnh:

```bash
sudo ss -lntp | grep ':22'
```

Kết quả cho thấy SSH đang lắng nghe trên địa chỉ `0.0.0.0:22` và `[::]:22`, cho phép máy khác kết nối đến dịch vụ SSH.

<img width="940" height="636" alt="image" src="https://github.com/user-attachments/assets/b6321c71-ae3b-48a7-bf5a-849cffb9974a" />


#### 4.2. Kiểm tra khả năng kết nối SSH từ Attacker

Từ máy Attacker, sử dụng lệnh sau để kiểm tra khả năng kết nối đến cổng SSH của Victim:

```bash
nc -vz 192.168.100.20 22
```

Kết quả trả về:

```text
Connection to 192.168.100.20 22 port [tcp/ssh] succeeded!
```

Điều này xác nhận cổng SSH trên Victim có thể truy cập được từ máy Attacker.

Tiếp theo, thực hiện đăng nhập SSH bằng tài khoản thử nghiệm:

```bash
ssh kb06test@192.168.100.20
```

Sau khi đăng nhập thành công, sử dụng lệnh:

```bash
whoami
```

Kết quả trả về `kb06test`, xác nhận tài khoản thử nghiệm có thể đăng nhập SSH bình thường.

<img width="817" height="56" alt="image" src="https://github.com/user-attachments/assets/77c335f2-b16a-4927-8ff9-caa48d136ac3" />


<img width="940" height="750" alt="image" src="https://github.com/user-attachments/assets/5b8c21f9-96f4-4390-8308-4d492fbe32fd" />


#### 4.3. Cài đặt và chuẩn bị công cụ Hydra

Trên máy Attacker, cài đặt công cụ Hydra để phục vụ kiểm thử:

```bash
sudo apt update
sudo apt install hydra -y
```

Sau khi cài đặt, kiểm tra công cụ bằng lệnh:

```bash
hydra -h
```

Kết quả hiển thị thông tin hướng dẫn sử dụng Hydra, xác nhận công cụ đã được cài đặt và có thể sử dụng.

Tiếp theo, tạo wordlist chứa một số mật khẩu thử nghiệm để phục vụ quá trình kiểm thử:

```bash
printf '%s\n' '123456' 'password' 'admin123' 'qwerty' '12345678' > ~/kb06_wordlist.txt
```

Kiểm tra nội dung wordlist:

```bash
cat ~/kb06_wordlist.txt
```

Wordlist gồm 5 mật khẩu thử nghiệm.

<img width="503" height="103" alt="image" src="https://github.com/user-attachments/assets/6e9c8c9b-9a00-4391-ab27-605f8e4a4478" />

#### 4.4. Thực hiện kiểm thử SSH Brute Force bằng Hydra

Sau khi xác nhận dịch vụ SSH hoạt động và máy Attacker có thể kết nối đến Victim, tiến hành mô phỏng hành vi đoán mật khẩu bằng Hydra trong môi trường lab.

Lệnh kiểm thử đã sử dụng:

```bash
hydra -l kb06test -P ~/kb06_wordlist.txt -t 5 -w 2 ssh://192.168.100.20
```

Trong đó:

- `-l kb06test`: Tài khoản được sử dụng để kiểm thử.
- `-P ~/kb06_wordlist.txt`: Đường dẫn đến danh sách mật khẩu thử nghiệm.
- `-t 5`: Sử dụng tối đa 5 tác vụ đồng thời.
- `-w 2`: Thời gian chờ cho mỗi lần thử.
- `ssh://192.168.100.20`: Dịch vụ SSH trên máy Victim.

**Kết quả thực nghiệm:**

Hydra hoàn thành quá trình kiểm thử và trả về:

```text
1 of 1 target completed, 0 valid password found
```

Như vậy, trong lần kiểm thử này, Hydra không tìm được mật khẩu hợp lệ trong danh sách đã cung cấp.

Cần lưu ý rằng kết quả trên không có nghĩa là dịch vụ SSH không tồn tại hoặc không thể đăng nhập. Trước đó, tài khoản `kb06test` đã được xác nhận đăng nhập SSH thành công bằng thông tin xác thực hợp lệ. Kết quả Hydra chỉ cho thấy mật khẩu tương ứng không được tìm thấy trong wordlist của lần kiểm thử này.

<img width="1190" height="162" alt="image" src="https://github.com/user-attachments/assets/bc7263c1-ce83-47ac-8255-2a8fede310df" />


#### 4.5. Xây dựng luật phát hiện SSH Brute Force trên Suricata

Trên máy Victim, bổ sung luật phát hiện các kết nối TCP SYN đến cổng SSH (22) được gửi lặp lại từ cùng một địa chỉ IP.

Luật được xây dựng trong file `local.rules`:

```text
alert tcp any any -> $HOME_NET 22 (msg:"LAB BRUTE SSH repeated connections"; flags:S; threshold:type both, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000004; rev:1;)
```

**Giải thích luật:**

- `alert tcp`: Tạo cảnh báo khi phát hiện lưu lượng TCP phù hợp.
- `any any`: Không giới hạn địa chỉ và cổng nguồn.
- `-> $HOME_NET 22`: Lưu lượng hướng đến máy thuộc HOME_NET, cổng đích 22.
- `msg:"LAB BRUTE SSH repeated connections"`: Nội dung cảnh báo.
- `flags:S`: Lọc các gói TCP có cờ SYN.
- `threshold:type both`: Kết hợp điều kiện ngưỡng để cảnh báo khi số lần xuất hiện đạt mức quy định.
- `track by_src`: Theo dõi số lần kết nối theo địa chỉ IP nguồn.
- `count 5, seconds 60`: Ngưỡng 5 lần trong khoảng 60 giây.
- `classtype:attempted-admin`: Phân loại hành vi có dấu hiệu thử truy cập trái phép.
- `sid:1000004`: Mã định danh duy nhất của luật.
- `rev:1`: Phiên bản luật.

Sau khi bổ sung luật, tiến hành kiểm tra cấu hình Suricata:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

Kết quả kiểm tra:

```text
53175 rules successfully loaded, 0 rules failed, 0 rules skipped
Configuration provided was successfully loaded. Exiting.
```

Điều này xác nhận cấu hình được tải thành công, không có luật nào bị lỗi khi nạp.

Sau đó khởi động lại dịch vụ:

```bash
sudo systemctl restart suricata
sudo systemctl is-active suricata
```

Kết quả trả về `active`, xác nhận Suricata đang hoạt động.

#### 4.6. Kiểm thử khả năng phát hiện lưu lượng SSH lặp lại

Sau khi hoàn tất cấu hình luật, tiến hành tạo lưu lượng kết nối SSH lặp lại từ máy Attacker đến máy Victim trong môi trường lab.

Để kiểm tra Suricata có ghi nhận cảnh báo hay không, sử dụng lệnh:

```bash
sudo grep '"signature_id":1000004' /var/log/suricata/eve.json | tail -n 10
```

Kết quả ghi nhận sự kiện cảnh báo có các thông tin:

| Trường thông tin | Giá trị ghi nhận |
|---|---|
| event_type | alert |
| signature_id | 1000004 |
| signature | LAB BRUTE SSH repeated connections |
| src_ip | 192.168.100.10 |
| dest_ip | 192.168.100.20 |
| dest_port | 22 |
| proto | TCP |
| severity | 1 |
| action | allowed |

Kết quả chứng minh Suricata đã nhận diện được các kết nối SSH lặp lại từ máy Attacker `192.168.100.10` đến máy Victim `192.168.100.20` và ghi nhận cảnh báo tương ứng với SID `1000004` trong file `eve.json`.

<img width="940" height="106" alt="image" src="https://github.com/user-attachments/assets/b79b4ae0-df8c-4e35-9c16-cb8740c0a63b" />


#### 4.7. Đánh giá kết quả thực nghiệm

Qua quá trình triển khai và kiểm thử, có thể rút ra các kết quả sau:

- Hai máy Attacker và Victim đã được kết nối trong cùng mạng lab và có thể liên lạc với nhau.
- Dịch vụ SSH trên Victim hoạt động bình thường, cổng 22 ở trạng thái LISTEN.
- Máy Attacker kết nối được đến cổng SSH và đăng nhập thành công bằng tài khoản thử nghiệm.
- Hydra đã được cài đặt và sử dụng để mô phỏng hành vi đoán mật khẩu SSH. Tuy nhiên, wordlist sử dụng trong lần kiểm thử chưa tìm được mật khẩu hợp lệ.
- Luật Suricata có SID `1000004` được nạp thành công và không phát sinh lỗi khi kiểm tra cấu hình.
- Suricata đã ghi nhận cảnh báo khi phát hiện các kết nối SSH lặp lại từ cùng một địa chỉ IP nguồn.

Như vậy, phần kiểm thử đã chứng minh được khả năng phát hiện hành vi kết nối SSH lặp lại bằng luật tự xây dựng trên Suricata. Tuy nhiên, cần phân biệt việc phát hiện kết nối lặp lại với việc xác nhận một cuộc tấn công Brute Force thành công: luật hiện tại dựa trên số lượng gói SYN, chưa kiểm tra trực tiếp số lần xác thực SSH thất bại.

### 5. Tổng hợp kết quả

| Nội dung đánh giá | Kết quả |
|---|---|
| Kết nối mạng Attacker – Victim | Thành công |
| Kiểm tra dịch vụ SSH | Thành công |
| Kiểm tra cổng 22 | Thành công |
| Đăng nhập SSH bằng tài khoản thử nghiệm | Thành công |
| Cài đặt Hydra | Thành công |
| Hydra tìm được mật khẩu trong wordlist | Không – 0 mật khẩu hợp lệ |
| Kiểm tra cấu hình Suricata | Thành công – 0 rules failed |
| Trạng thái dịch vụ Suricata | Active |
| Phát hiện bằng luật tự xây dựng SID 1000004 | Có |
| Ghi nhận cảnh báo trong eve.json | Có |

### 6. Kết luận

Nhiệm vụ KB04 đã hoàn thành phần triển khai môi trường, kiểm tra dịch vụ SSH, mô phỏng hành vi đoán mật khẩu và xây dựng luật phát hiện trên Suricata.

Kết quả thực nghiệm cho thấy Suricata có thể phát hiện và ghi nhận các kết nối SSH lặp lại từ máy Attacker đến máy Victim thông qua luật tự xây dựng có SID `1000004`.

Mặc dù Hydra chưa tìm được mật khẩu hợp lệ trong wordlist đã sử dụng, hệ thống vẫn ghi nhận được cảnh báo tương ứng với hành vi kết nối SSH lặp lại. Đây là cơ sở để đánh giá khả năng giám sát và phát hiện của Suricata trong kịch bản KB04.


## Tệp nguồn và minh chứng gốc

Thư mục nguồn trong repository ban đầu: [`06-ssh-bruteforce`](https://github.com/phanyen206/Suricata/tree/main/scenarios/06-ssh-bruteforce). Các tệp nhị phân như PCAP, ảnh chụp và tài liệu DOCX (nếu có) hiện vẫn được giữ tại repository nguồn; README này liên kết về nguồn để người đọc tải/xem, không thay thế bằng dữ liệu giả.
