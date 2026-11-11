> **Hướng dẫn người đọc:** README này mô tả mục tiêu, môi trường, thứ tự tái lập và cách kiểm tra kết quả. Hãy đọc phần môi trường và lệnh trước khi chạy script; cập nhật IP/interface theo lab của bạn. Chỉ chạy trong mạng ảo được phép.

# KB12 – KỊCH BẢN REFLECTED XSS — REFLECTED XSS VỚI SURICATA IDS

> Báo cáo thực nghiệm và hướng dẫn tái lập. Nguồn đối chiếu: `Suricata-main.zip/scenarios/14-reflected-xss/Kịch bản 14.docx`, `README.md`, `attack.sh`, cùng ảnh terminal của phiên thực hành. Các kết quả chưa đo được được đánh dấu **CHƯA XÁC MINH**, không tự điền số liệu.

## 1. Mục tiêu

Thực nghiệm phát hiện dấu hiệu Reflected Cross-Site Scripting (XSS) trong HTTP bằng Suricata IDS; so sánh hai lần chạy: RUN 1 sử dụng bộ luật ET Open và RUN 2 sử dụng luật phát hiện XSS tự viết, `sid:1000016`. Thử thêm một tệp PCAP lưu lượng khác nhằm quan sát khả năng phát sinh cảnh báo giả. Mã ATT&CK được tài liệu gốc gợi ý là T1190; đây là ánh xạ tham khảo, không đồng nghĩa đã chứng minh khai thác thành công ứng dụng.

## 2. Phạm vi và môi trường

- Nền tảng: hai máy Ubuntu chạy trên Oracle VirtualBox (Attacker và Victim).
- IP quan sát thực tế từ ảnh: Attacker `192.168.100.4`, Victim `192.168.100.3`, giao diện mạng `enp0s3`.
- Web server trên Victim: Apache/2.4.66 (Ubuntu), cổng TCP/80; lệnh `curl -I` trả về `HTTP/1.1 200 OK`.
- IDS: Suricata 8.0.3 RELEASE.
- Công cụ: `curl`, `tcpdump`, `capinfos`, `grep`, `suricata`, `suricata-update` (cập nhật ET Open).
- Tài liệu gốc dùng IP mẫu `10.0.2.10` và trong `attack.sh` dùng `192.168.100.20`; các IP này là ví dụ, **không phải IP thực nghiệm**. Phải dùng IP thực tế của máy Victim.

<img width="876" height="315" alt="image" src="https://github.com/user-attachments/assets/5c097b1e-e1f8-4553-b08f-b58b10fd30ff" />
<img width="655" height="58" alt="image" src="https://github.com/user-attachments/assets/e1cea10f-3a36-4639-8e43-d16dbb75b66d" />

## 3. Kiểm tra kết nối và dịch vụ

### Trên Attacker

```bash
ip -br a
ping -c 4 192.168.100.3
curl -I http://192.168.100.3/
```

### Trên Victim

```bash
ip -br a
sudo systemctl status apache2 --no-pager
curl -I http://127.0.0.1/
sudo suricata -V
sudo suricata -T -c /etc/suricata/suricata.yaml
```

**Kết quả đã thấy:** Ping thành công (4/4), HTTP trả 200 OK, Apache hoạt động. Cấu hình Suricata kiểm tra thành công trong ảnh terminal. 
<img width="620" height="192" alt="image" src="https://github.com/user-attachments/assets/d4e47a5f-51b5-42ae-9ea0-a1a7c3e4c6b9" />

## 4. Chuẩn bị dữ liệu tấn công và thu PCAP

Tài liệu gốc `attack.sh` sử dụng lệnh mẫu:

```bash
#!/bin/bash
VICTIM="192.168.100.20"  # IP mẫu trong repo; thay bằng 192.168.100.3
curl -G "http://$VICTIM/search" --data-urlencode "q=<script>alert(1)</script>"
```

Trong lần thực nghiệm đã ghi nhận ở ảnh, request được gửi đến `192.168.100.3:80` với chuỗi URL-encoded chứa `%3Cscript%3Ealert%281%29%3C%2Fscript%3E`. Đây là **bằng chứng gửi yêu cầu chứa dấu hiệu XSS**, không phải bằng chứng ứng dụng thực thi JavaScript hay có lỗ hổng Reflected XSS thực sự.

### Thu lại PCAP (chỉ khi cần tái lập)

Trên Victim mở terminal thứ nhất:

```bash
sudo tcpdump -i enp0s3 -nn -s 0 -w ~/sample-xss.pcap 'tcp port 80'
```

Trên Attacker mở terminal khác:

```bash
curl -G 'http://192.168.100.3/search' --data-urlencode 'q=<script>alert(1)</script>'
```

Dừng tcpdump trên Victim bằng `Ctrl+C`. Nếu ứng dụng không có `/search`, HTTP 404 vẫn có thể chứa yêu cầu XSS trong PCAP; không kết luận đã khai thác được trang web.

```bash
sudo tcpdump -nn -A -r ~/sample-xss.pcap 'tcp port 80' | grep -Ei 'GET |Host:|script'
```

<img width="1088" height="708" alt="image" src="https://github.com/user-attachments/assets/11368411-f863-48a4-85d3-338802cbbc80" />
 <img width="781" height="329" alt="image" src="https://github.com/user-attachments/assets/a857a8b2-f27a-4cd5-97f7-69f00ced54b9" />

## 5. Chuẩn bị ET Open và luật tùy chỉnh

Tài liệu gốc yêu cầu RUN 1 chỉ ET Open và RUN 2 thêm luật tự viết. Không nhầm lẫn `-S` (nạp duy nhất tệp rule chỉ định) với `-s` (nạp thêm rule vào tập rule cấu hình).

### Kiểm tra ET Open

```bash
sudo suricata-update
sudo ls -lh /var/lib/suricata/rules/suricata.rules
sudo suricata -T -c /etc/suricata/suricata.yaml
```

Ảnh trước đó cho thấy tệp `/var/lib/suricata/rules/suricata.rules` đã được tạo sau khi cập nhật, kích thước khoảng 44 MB; **không có nghĩa mọi luật đều đã được kích hoạt**. **<img width="955" height="80" alt="image" src="https://github.com/user-attachments/assets/fd65d26a-cad6-4f21-ad3f-e289d13de612" />

### Luật tự viết

Tài liệu `Kịch bản 14.docx` đưa ra luật mẫu:

```suricata
alert http any any -> any any (msg:"KB12 Reflected XSS Attack Detected"; content:"q="; content:"<script>"; sid:1000016; rev:1;)
```

Tuy nhiên, **luật thực tế đã chạy trong VM** được thể hiện trong ảnh và sử dụng `http.uri.raw` với chuỗi URL-encoded `%3Cscript%3E`, nội dung tương đương:

```suricata
alert http any any -> any any (msg:"CANH BAO: Phat hien XSS Test"; flow:established,to_server; http.uri.raw; content:"%3Cscript%3E"; nocase; sid:1000016; rev:1;)
```

Đây là hai cách viết **khác nhau**. Để báo cáo phản ánh đúng thực nghiệm, sử dụng luật thứ hai cho RUN 2; kiểm tra lại bằng `sudo cat -n /etc/suricata/rules/local.rules`. Luật có thể nhận diện chuỗi cụ thể nhưng không chứng minh lỗ hổng XSS. Đặc biệt, nó có thể bỏ sót các biến thể mã hóa khác.

```bash
sudo cat -n /etc/suricata/rules/local.rules
sudo suricata -T -c /etc/suricata/suricata.yaml -S /etc/suricata/rules/local.rules
```

<img width="992" height="137" alt="image" src="https://github.com/user-attachments/assets/cf066bd0-e05c-49d3-8d53-9de5292b2d28" />


## 6. RUN 1 — Bộ luật ET Open

### Lệnh tái lập đúng theo mục tiêu tài liệu

```bash
mkdir -p ~/kb14-final/run1
sudo suricata -r ~/sample-xss.pcap \
  -c /etc/suricata/suricata.yaml \
  -S /var/lib/suricata/rules/suricata.rules \
  -l ~/kb14-final/run1 -k none
sudo ls -lh ~/kb14-final/run1/
sudo cat ~/kb14-final/run1/fast.log
```

`-k none` bỏ qua kiểm tra checksum khi phát lại PCAP, giúp hạn chế nhiễu do checksum offloading; nếu cần so sánh đúng bản chạy gốc, phải giữ nguyên tham số của lần chạy và ghi rõ thay đổi. Lệnh trên chỉ dùng ET Open qua `-S`, không nạp `local.rules` tự viết.

### Kết quả có bằng chứng

Trong ảnh của RUN 1, file `~/kb14-final/run1/fast.log` tồn tại, cùng `eve.json`, `stats.log`, `suricata.log`. Có 15 dòng cảnh báo dạng `[1:2200074:2] SURICATA TCPv4 invalid checksum`. Đây là **cảnh báo checksum**, không phải cảnh báo phát hiện XSS. Lệnh `grep -iE 'xss|cross.site|script'` trên log không trả về dòng khớp. Chưa có số đo độ trễ cảnh báo.

<img width="777" height="292" alt="image" src="https://github.com/user-attachments/assets/b46c3aea-ad4e-4397-8fc2-c96b6ccb8bc8" />
 <img width="854" height="186" alt="image" src="https://github.com/user-attachments/assets/7c4588b8-d9e5-4d6f-b526-70a968df8930" />

## 7. RUN 2 — Luật tự viết SID 1000016

### Lệnh đã sử dụng trong thực nghiệm

```bash
mkdir -p ~/kb14-final/run2
sudo suricata -r ~/sample-xss.pcap \
  -S /etc/suricata/rules/local.rules \
  -l ~/kb14-final/run2 -k none
sudo cat ~/kb14-final/run2/fast.log
```

**Quan trọng:** lệnh thực tế dùng `-S local.rules`, nghĩa là chỉ kiểm thử bộ luật trong tệp đó, **không chứng minh cấu hình ET Open + luật nhóm đồng thời** như mô tả mục tiêu tài liệu gốc. Nếu cần chứng minh đúng yêu cầu ET Open kết hợp luật nhóm, thực hiện thêm một lần chạy riêng:

```bash
mkdir -p ~/kb14-final/run2-combined
sudo suricata -r ~/sample-xss.pcap \
  -c /etc/suricata/suricata.yaml \
  -S /var/lib/suricata/rules/suricata.rules \
  -s /etc/suricata/rules/local.rules \
  -l ~/kb14-final/run2-combined -k none
sudo grep '1000016' ~/kb14-final/run2-combined/fast.log
```

### Kết quả có bằng chứng

Trong RUN 2 đã xuất hiện cảnh báo `CANH BAO: Phat hien XSS Test`, SID `1000016`, ưu tiên 3, luồng `192.168.100.4:46632 -> 192.168.100.3:80`. Tệp `fast.log` trong thư mục `~/kb14-final/run2/` có dung lượng khoảng 166 bytes tại thời điểm chụp. Đây là bằng chứng luật tự viết nhận diện mẫu request XSS.

<img width="754" height="489" alt="image" src="https://github.com/user-attachments/assets/c8eee988-1607-4675-b729-ba1f34c16d76" />
 <img width="964" height="151" alt="image" src="https://github.com/user-attachments/assets/e51f8e71-c8b9-4bab-8268-41e42dffdf40" />

## 8. Kiểm thử lưu lượng benign (kiểm tra cảnh báo giả)

### Lệnh đã chạy

```bash
mkdir -p ~/kb14-final/benign
sudo suricata -r ~/sample.pcap \
  -S /etc/suricata/rules/local.rules \
  -l ~/kb14-final/benign -k none
sudo cat ~/kb14-final/benign/fast.log
```

### Kết quả có bằng chứng

Suricata xử lý thành công `sample.pcap`: **65 gói tin, 5.695 bytes dữ liệu**; lệnh `cat fast.log` không hiển thị cảnh báo. Đây là bằng chứng **0 cảnh báo trong mẫu đã thử** (cần kiểm tra `wc -l` để xác nhận tệp tồn tại và rỗng). Không đủ cơ sở để tuyên bố tỷ lệ false positive tổng thể bằng 0; hơn nữa `sample.pcap` chưa được kiểm chứng độc lập là tập lưu lượng HTTP lành tính đại diện.

```bash
sudo ls -lh ~/kb14-final/benign/
sudo wc -l ~/kb14-final/benign/fast.log
sudo capinfos ~/sample.pcap
```

<img width="961" height="493" alt="image" src="https://github.com/user-attachments/assets/21c909ed-812a-47e7-b715-963a53106a42" />
 
## 9. Tổng hợp so sánh

| Tiêu chí | RUN 1: ET Open | RUN 2: local.rules | Benign: local.rules |
|---|---|---|---|
| Tệp đầu vào | sample-xss.pcap | sample-xss.pcap | sample.pcap |
| Dữ liệu đã quan sát | PCAP XSS | PCAP XSS | 65 gói tin |
| Cảnh báo XSS SID 1000016 | Không ghi nhận | Có, 1 dòng được thấy | Không ghi nhận |
| Cảnh báo khác | 15 dòng invalid checksum trong log | Không kết luận nếu chưa kiểm tra toàn bộ log | Không có đầu ra từ fast.log |
| Kết luận | Không phát hiện XSS trong mẫu và cấu hình đã thử | Luật tự viết phát hiện mẫu XSS | Không phát sinh cảnh báo trên mẫu này |

**Lưu ý phương pháp:** RUN 1 và RUN 2 thực tế được kiểm thử với `-S` trỏ tới hai bộ luật khác nhau. Vì thế chưa được gọi là thí nghiệm so sánh ET Open với **ET Open + custom** cho đến khi hoàn tất `run2-combined`. Số cảnh báo XSS, thời gian xử lý, tỷ lệ phát hiện, độ trễ trung bình, tỷ lệ false positive trên tập dữ liệu lớn: **CHƯA XÁC MINH**.

## 10. Phân tích kỹ thuật

Chuỗi `<script>alert(1)</script>` khi đi qua tham số truy vấn có thể được URL-encode. Luật sử dụng `http.uri.raw` và `content:"%3Cscript%3E"` sẽ khớp khi dạng mã hóa đó xuất hiện trong URI thô. Đó là phát hiện dấu hiệu payload, không phải xác minh trình duyệt thực thi mã. Cảnh báo checksum ở RUN 1 thuộc lớp kiểm tra gói tin; không nên cộng vào số alert XSS. Việc kiểm thử bằng PCAP có thể chịu ảnh hưởng của checksum offloading, nội dung PCAP và cách cấu hình Suricata.

## 11. Hạn chế và hướng phát triển

- Mẫu tấn công chỉ bao phủ chuỗi script cơ bản, chưa kiểm thử các biến thể URL encoding, HTML entities, thay đổi chữ hoa/thường, payload khác hoặc các trường hợp vượt qua bộ lọc.
- Chưa chứng minh trang web phản chiếu dữ liệu vào HTML hoặc thực thi JavaScript; do đó không tuyên bố khai thác Reflected XSS thành công.
- RUN 2 hiện tại chỉ dùng custom rules; cần chạy thêm `run2-combined` nếu yêu cầu đúng ET Open kết hợp custom.
- Không có phép đo độ trễ trung bình hay đánh giá thống kê false positive. Các trường trong README gốc còn để trống, phải điền sau khi đo.
- Không nên công bố IP ngoài môi trường lab, dữ liệu riêng tư hoặc file PCAP có thông tin nhạy cảm trên GitHub.

## 12. Kết luận

Thực nghiệm đã xác minh kết nối Attacker–Victim, dịch vụ HTTP, cấu hình Suricata, thu được PCAP chứa yêu cầu mang dấu hiệu XSS, chạy RUN 1, RUN 2 và mẫu benign. RUN 1 không ghi nhận cảnh báo XSS trong log được kiểm tra; RUN 2 với luật tự viết SID 1000016 ghi nhận cảnh báo XSS; mẫu benign không sinh cảnh báo trong `fast.log`. **Chưa đủ bằng chứng để khẳng định đã hoàn thành hoàn toàn yêu cầu RUN 2 kết hợp ET Open + custom hoặc đánh giá độ trễ và false positive định lượng.**

## 13. Bố cục GitHub đề xuất

```text
scenarios/14-reflected-xss/
├── README.md
├── attack.sh
├── custom-rule.rules
├── evidence/
│   ├── 01-ip-attacker-victim.png
│   ├── 02-http-suricata.png
│   ├── 03-curl-payload.png
│   ├── 04-pcap-request.png
│   ├── 05-etopen-update.png
│   ├── 06-custom-rule.png
│   ├── 07-run1-log.png
│   ├── 08-run2-alert.png
│   ├── 09-benign-no-alert.png
│   └── 10-run2-combined.png
└── results/
    ├── run1-fast.log
    ├── run2-fast.log
    ├── benign-fast.log
    └── run2-combined-fast.log
```

Ảnh có thể chụp bằng công cụ Screenshot của Ubuntu hoặc screenshot VirtualBox. Đặt đúng tên và lưu vào `evidence/`, rồi thêm vào README cú pháp `![Mô tả](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/14-reflected-xss/evidence/08-run2-alert.png)`. Không đưa ảnh minh họa không phải kết quả thực tế.

## 14. Lệnh tổng hợp bằng chứng trước khi nộp

```bash
sudo ls -lh ~/kb14-final/{run1,run2,benign}/
sudo wc -l ~/kb14-final/{run1,run2,benign}/fast.log
sudo grep -E '1000016|XSS' ~/kb14-final/run2/fast.log
sudo grep -Ei 'xss|cross.site|script' ~/kb14-final/run1/fast.log || true
sudo cat -n /etc/suricata/rules/local.rules
```

Chỉ bổ sung số liệu và ảnh chụp sau khi lệnh đã chạy thực tế. Không dùng ảnh `run1` có cảnh báo checksum để kết luận đã phát hiện XSS.


## Tệp nguồn và minh chứng gốc

Thư mục nguồn trong repository ban đầu: [`14-reflected-xss`](https://github.com/phanyen206/Suricata/tree/main/scenarios/14-reflected-xss). Các tệp nhị phân như PCAP, ảnh chụp, gói minh chứng hoặc tài liệu DOCX (nếu có) hiện vẫn được giữ tại repository nguồn; README này liên kết về nguồn để người đọc tải/xem, không thay thế bằng dữ liệu giả.
