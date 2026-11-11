> **Hướng dẫn người đọc:** README này mô tả mục tiêu, môi trường, thứ tự tái lập và cách kiểm tra kết quả. Hãy đọc phần môi trường và lệnh trước khi chạy script; cập nhật IP/interface theo lab của bạn. Chỉ chạy trong mạng ảo được phép.

# KB02 – Phát hiện hành vi dò quét cổng UDP (nmap -sU) trên máy chủ nội bộ

| Mục | Nội dung |
|---|---|
| Người thực hiện | Thư |
| Nhóm kịch bản | KB01–KB05: Trinh sát |
| ATT&CK | T1046 – Network Service Discovery |
| Công cụ | nmap 7.98 |
| SID luật nhóm | **9000201**, **9000202** (lưu trong `custom-rule.rules`, không dùng `rules/local.rules`) |
| Thời gian thực nghiệm | Bắt PCAP và Run 1: 03/11/2026 – Run 2: 04/11/2026 |
| Trạng thái | Đã hoàn thành: tạo lưu lượng, Run 1, Run 2, kiểm thử lưu lượng bình thường |
| Kết luận nhanh | ET Open **3/5** (chưa đạt, chỉ nhờ một luật SSDP). Luật nhóm **5/5**, **0 cảnh báo sai**, độ trễ trung bình **≈ 2,9 giây** |

---

## Phần I – Xây dựng bài toán

### 1. Bối cảnh

Tiếp nối KB01: một thiết bị trong mạng nội bộ đã bị kẻ tấn công kiểm soát. Ngoài các dịch vụ TCP, kẻ tấn công còn dò các dịch vụ **UDP** trên máy chủ, như DNS, NTP, SNMP, NetBIOS, SSDP. Đây là những dịch vụ thường bị bỏ quên khi cấu hình bảo mật, và nhiều dịch vụ trong số đó có thể bị lợi dụng để khuếch đại tấn công hoặc lộ thông tin.

### 2. Vấn đề bảo mật

Quét UDP khó phát hiện hơn quét TCP:
- UDP không có bắt tay ba bước, nên không có dấu hiệu kiểu "nhiều gói SYN".
- Cổng đóng được nhận diện qua gói **ICMP port unreachable** do máy đích gửi về.
- Cổng mở hoặc bị lọc thường không có phản hồi nào.
- Với một số cổng phổ biến, nmap gửi gói kèm dữ liệu của chính giao thức đó (DNS, SSDP…), nên gói quét trông giống lưu lượng thật.

### 3. Bài toán

Dùng Suricata IDS phát hiện hành vi một thiết bị gửi gói UDP tới nhiều cổng của máy chủ trong thời gian ngắn, đồng thời không cảnh báo nhầm với lưu lượng UDP hợp lệ như DNS.

### 4. Tiêu chí đánh giá (giống KB01)

Bộ luật được coi là **đạt** khi thỏa mãn đồng thời:
1. Có cảnh báo liên quan đến quét UDP ở **cả 5 lần quét**.
2. Cảnh báo gắn đúng cặp máy **192.168.100.10 (Attacker)** và **192.168.100.20 (Victim)**.
3. **Không có cảnh báo quét** trên 12 PCAP lưu lượng bình thường.

Số lượng cảnh báo **không** được dùng làm tiêu chí so sánh.

### 5. Quy trình

Quy trình giống KB01: xây dựng bài toán → tạo lưu lượng và thu PCAP → Run 1 với ET Open. Nếu chưa đạt thì bổ sung luật riêng và chạy Run 2 trên đúng các PCAP đó → đánh giá và viết báo cáo.

---

## Phần II – Môi trường thực nghiệm

| Thành phần | Cấu hình |
|---|---|
| Máy Attacker | Ubuntu, hostname `Ubuntu-Attacker`, `ens33`: **192.168.100.10/24** |
| Máy Victim | Ubuntu, hostname `Ubuntu-Victim`, `ens33`: **192.168.100.20/24** |
| IDS | Suricata **8.0.3**, chạy đọc PCAP ngoại tuyến (`suricata -r`, `-k none`) |
| Bộ luật Run 1 | ET Open (`/var/lib/suricata/rules/suricata.rules`), giống KB01 |
| `HOME_NET` / `EXTERNAL_NET` | `[192.168.100.0/24]` / `!$HOME_NET` |
| Bắt gói | tcpdump trên Victim, `host 192.168.100.10`, dừng bằng Ctrl+C sau khi nmap kết thúc |

Ghi chú môi trường:
- Từ KB02, hostname của hai máy đã được đổi thành `Ubuntu-Attacker` và `Ubuntu-Victim` để ảnh chụp dễ phân biệt. Cấu hình IP và Suricata giống KB01, xem minh chứng IP, `ip route` và `suricata -T` trong README KB01.
- Sau khi mở lại máy ảo từ trạng thái suspend, đồng hồ được đặt bằng tay. Kết quả là **đồng hồ Attacker chậm hơn Victim khoảng 2 phút**. Mọi thời điểm trong báo cáo này đều lấy theo **đồng hồ Victim** (PCAP và Suricata).

![Victim sau khi đổi hostname và chỉnh giờ](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/01-victim-hostname-date.png)
*Hình 1. Victim sau khi đổi hostname (`Ubuntu-Victim`) và chỉnh đồng hồ về 03/11.*

### Dịch vụ UDP đang mở trên Victim

| Cổng | Dịch vụ | Attacker truy cập được |
|---|---|---|
| 53 | dnsmasq (DNS, dùng cho lưu lượng bình thường) | Có |
| 5353 | avahi-daemon (mDNS) | Có |
| 3702 | python3 (WS-Discovery) | Có (không nằm trong các dải cổng được quét) |
| 127.0.0.53/54:53, 127.0.0.1:323 | systemd-resolved, chronyd | Không, chỉ cục bộ |

![Cổng UDP đang mở trên Victim](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/04-victim-udp-listening-ports.png)
*Hình 2. `sudo ss -ulnp` trên Victim.*

---

## Phần III – Tạo lưu lượng và thu PCAP

### 1. Cách thực hiện

```bash
# Victim – bật trước, dừng bằng Ctrl+C khoảng 5 giây sau khi nmap kết thúc
sudo tcpdump -i ens33 -nn -s 0 -Z $USER -w ~/kb_pcaps/kb02_runN.pcap host 192.168.100.10
# Attacker
sudo nmap -sU <tham số> 192.168.100.20 -oN kb02_runN.txt
```

Quét UDP chậm và khó đoán thời gian, nên không dùng `timeout` như KB01. Lệnh chi tiết nằm trong [`lenh_attacker_victim.txt`](lenh_attacker_victim.txt).

### 2. Năm lần quét

| Lần | Lệnh nmap | Số cổng | Thời gian | UDP gửi | ICMP nhận | open / closed / open\|filtered |
|---|---|---|---|---|---|---|
| run1 (`attack.sh`) | `-sU --top-ports 100` | 100 | 108,34 s | 276 | 111 | 1 / 98 / 1 |
| run2 | `-sU -T2 --top-ports 20` | 20 | 19,90 s | 55 | 27 | 1 / 19 / 0 |
| run3 | `-sU -T4 --top-ports 100` | 100 | 52,28 s | 646 | 60 | 1 / 55 / 44 |
| run4 | `-sU -T4 --top-ports 200` | 200 | 180,74 s | 613 | 188 | 1 / 170 / 29 |
| run5 | `-sU -p 53,67,69,123,137,161,500,514,1900,5353` | 10 | 5,73 s | 56 | 13 | 1 / 7 / 2 |

Nhận xét:
- **Cổng 53 (dnsmasq)** được phát hiện `open` ở cả 5 lần. 5353 (avahi) là `open|filtered` ở run1 và run5.
- **Thời gian quét phụ thuộc chủ yếu vào số cổng**, khoảng 1 giây mỗi cổng ở run1 và run2. Nguyên nhân là Linux giới hạn tốc độ gửi ICMP port unreachable, nên nmap phải chờ và gửi lại (khoảng 2,75 gói UDP cho mỗi cổng ở cả run1 lẫn run2). Ở mức T2 và T3, tốc độ quét gần như không tạo khác biệt.
- **Ở -T4 (run3)**, nmap gửi dồn dập (khoảng 6,5 gói cho mỗi cổng), còn Victim chỉ kịp trả 60 gói ICMP. Kết quả là **44 cổng đóng bị ghi nhầm thành `open|filtered`**: nhanh gấp đôi run1 nhưng kém chính xác hơn.
- **Ở run4**, nmap báo `retransmission cap hit (6)` rồi **tự giảm tốc độ**. Run4 quét gấp đôi số cổng của run3 nhưng gửi ít gói hơn (613 so với 646), và tỉ lệ ghi nhầm thấp hơn (29/200).
- **Cổng 1900 ở run5** bị ghi `open|filtered` dù không có dịch vụ nào lắng nghe (Hình 2). Nhiều khả năng ICMP trả về cho cổng này bị giới hạn tốc độ chặn mất.

### 3. Minh chứng từng lần quét

**run1:** `--top-ports 100`, đúng lệnh `attack.sh`

![run1 – Attacker](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/kb02-run1-attacker.png)
![run1 – Victim](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/kb02-run1-victim.png)
*Hình 3. run1: nmap quét 100 cổng trong 108,34 s; PCAP có 276 gói UDP và 111 gói ICMP.*

**run2:** `-T2 --top-ports 20`

![run2 – Attacker](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/kb02-run2-attacker.png)
![run2 – Victim](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/kb02-run2-victim.png)
*Hình 4. run2: 20 cổng trong 19,90 s; 55 gói UDP và 27 gói ICMP.*

**run3:** `-T4 --top-ports 100`

![run3 – Attacker](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/kb02-run3-attacker.png)
![run3 – Victim](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/kb02-run3-victim.png)
*Hình 5. run3: 52,28 s, 44 cổng `open|filtered`; 646 gói UDP và 60 gói ICMP.*

**run4:** `-T4 --top-ports 200`

![run4 – Attacker](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/kb02-run4-attacker.png)
![run4 – Victim](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/kb02-run4-victim.png)
*Hình 6. run4: 180,74 s, có cảnh báo "retransmission cap hit"; 613 gói UDP và 188 gói ICMP.*

**run5:** 10 cổng dịch vụ cụ thể

![run5 – Attacker](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/kb02-run5-attacker.png)
![run5 – Victim](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/kb02-run5-victim.png)
*Hình 7. run5: 5,73 s; 56 gói UDP và 13 gói ICMP.*

![Danh sách PCAP KB02](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/05-pcap-list.png)
*Hình 8. Năm PCAP của KB02.*

### 4. Lưu lượng bình thường

KB02 dùng chung bộ 12 PCAP `benign_01` … `benign_12` với KB01 (xem README và `lenh_benign.txt` của KB01). Bộ này có chứa lưu lượng UDP hợp lệ: 20 truy vấn DNS (`benign_06`) và các truy vấn DNS kết hợp (`benign_09`, `benign_11`).

---

## Phần IV – Run 1: ET Open mặc định

### 1. Kiểm tra trước khi chạy

Lọc các luật ET SCAN liên quan đến UDP:
- **Đang bật:** chỉ có luật cho công cụ hoặc dịch vụ cụ thể (Amap, Sipvicious và các SIP scanner khác, TFTP, UPnP 1900, Mirai UDP…). **Không có luật nhận diện chung kiểu quét `nmap -sU`.**
- **Đang tắt:** chỉ có NBTStat và luật cho crawler.

![Luật ET SCAN liên quan UDP đang bật](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/02-et-open-udp-rules-enabled.png)
![Luật ET SCAN liên quan UDP đang bật (tiếp) và bị tắt](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/03-et-open-udp-rules-enabled-disabled.png)
*Hình 9–10. Các luật ET SCAN có liên quan đến UDP trong ET Open.*

### 2. Lệnh chạy

```bash
for f in kb02_run*.pcap; do
  n=${f%.pcap}; mkdir -p out_kb02/run1/$n
  sudo suricata -c /etc/suricata/suricata.yaml -k none -S $RULES -r $f -l out_kb02/run1/$n
done
```

Run 1 trên lưu lượng bình thường **dùng lại kết quả của KB01**, vì ET Open, `suricata.yaml` và 12 PCAP đều giữ nguyên.

### 3. Kết quả

| PCAP | Cảnh báo liên quan | Cảnh báo khác |
|---|---|---|
| kb02_run1 (`attack.sh`) | **0** | 3 × SID 2200075 `UDPv4 invalid checksum` |
| kb02_run2 | **1 × SID 2019102** `ET DOS Possible SSDP Amplification Scan in Progress` | 3 × 2200075 |
| kb02_run3 | **1 × SID 2019102** | 3 × 2200075 |
| kb02_run4 | **0** | 3 × 2200075 |
| kb02_run5 | **1 × SID 2019102** | 3 × 2200075 |

![Run 1 – tóm tắt](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/06-run1-summary.png)
*Hình 11. Run 1 trên 5 PCAP KB02.*

Cảnh báo 2200075 là gói DNS trả lời từ Victim. Lỗi checksum xuất hiện do checksum offload khi bắt gói ngay trên Victim, cùng nguyên nhân như ở KB01, và không liên quan đến hành vi quét.

### 4. Phân tích: vì sao chỉ 3/5

SID 2019102 **không phải luật phát hiện quét UDP**. Đây là luật nhóm *ET DOS* nhận diện gói SSDP `M-SEARCH` tới cổng 1900:

```
alert udp any any -> $HOME_NET 1900 (msg:"ET DOS Possible SSDP Amplification Scan in Progress";
  content:"M-SEARCH * HTTP/1.1"; content:"ST|3a 20|ssdp|3a|all|0d 0a|"; nocase; distance:0;
  threshold: type both,track by_src,count 2,seconds 60; ... sid:2019102; rev:1; ...)
```

![Luật 2019102](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/07-sid2019102-rule.png)
*Hình 12. Nội dung luật SID 2019102.*

Khi quét `-sU`, nmap gửi đúng gói SSDP này vào cổng 1900. Luật chỉ cảnh báo khi có **từ 2 gói như vậy trong 60 giây**. Số gói tới cổng 1900 trong từng PCAP:

| PCAP | Gói tới cổng 1900 | Đủ ngưỡng (≥ 2) | Cảnh báo 2019102 |
|---|---|---|---|
| run1 | 1 | Không | 0 |
| run2 | 2 | Có | 1 |
| run3 | 6 | Có | 1 |
| run4 | 1 | Không | 0 |
| run5 | 5 | Có | 1 |

![Số gói tới cổng 1900](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/08-port1900-count.png)
*Hình 13. Số gói UDP gửi tới cổng 1900 trong từng PCAP.*

Như vậy, ET Open phát hiện được hay không **phụ thuộc vào việc nmap có gửi lại gói tới cổng 1900 hay không**, tức là phụ thuộc vào cổng 1900 có nằm trong dải quét và có nhận phản hồi ICMP kịp hay không. Nó không dựa trên hành vi quét nhiều cổng UDP. Lần quét theo đúng `attack.sh` (run1) **không bị phát hiện**. Một cuộc quét không chạm tới cổng 1900 cũng sẽ không bị phát hiện.

**→ Run 1 chưa đạt (3/5). Cần bổ sung luật riêng và chạy Run 2.**

---

## Phần V – Run 2: ET Open + luật nhóm

### 1. Dữ liệu dùng để thiết kế luật

Quét UDP để lại hai dấu hiệu hành vi. Hai dấu hiệu này đã được đếm trên cả 17 PCAP **trước khi** chọn ngưỡng:

| PCAP | UDP rỗng (độ dài UDP = 8 byte) từ Attacker | ICMP port unreachable (type 3, code 3) |
|---|---|---|
| run1 | 75 | 111 |
| run2 | 17 | 27 |
| run3 | 186 | 60 |
| run4 | 212 | 188 |
| run5 | **1** | 13 |
| 12 file benign | **0** | **0** |

![Đếm dấu hiệu trên 17 PCAP](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/09-empty-udp-icmp-count.png)
*Hình 14. Số gói UDP rỗng và ICMP port unreachable trong 5 PCAP tấn công và 12 PCAP bình thường.*

- Lưu lượng UDP bình thường như DNS **luôn có dữ liệu**, nên gói UDP rỗng là dấu hiệu đặc trưng của quét.
- run5 gần như không có gói UDP rỗng, vì cả 10 cổng đều là dịch vụ mà nmap gửi kèm dữ liệu riêng. Do đó cần thêm luật dựa trên **phản hồi ICMP từ Victim**.

### 2. Luật bổ sung (`custom-rule.rules`)

```
alert udp any any -> $HOME_NET any (msg:"KB02 UDP scan - nhieu goi UDP rong"; dsize:0; threshold: type both, track by_src, count 10, seconds 60; classtype:attempted-recon; sid:9000201; rev:1;)
alert icmp $HOME_NET any -> any any (msg:"KB02 UDP scan - nhieu ICMP port unreachable"; itype:3; icode:3; threshold: type both, track by_dst, count 10, seconds 60; classtype:attempted-recon; sid:9000202; rev:1;)
```

| Luật | Dấu hiệu | Ngưỡng | Ghi chú |
|---|---|---|---|
| **9000201** | Gói UDP **không có dữ liệu** (`dsize:0`) gửi vào `HOME_NET` từ **bất kỳ nguồn nào** | ≥ 10 gói / 60 s, đếm theo nguồn | Dấu hiệu phía Attacker; không phụ thuộc Victim có trả lời hay không |
| **9000202** | Victim gửi **ICMP port unreachable** | ≥ 10 gói / 60 s, đếm theo **đích** (máy đang quét) | Bắt được trường hợp nmap gửi gói có dữ liệu (run5). Cảnh báo hiển thị chiều **.20 → .10** vì gói ICMP do Victim gửi |

Hai luật đều dùng `any`/`$HOME_NET` thay vì `$EXTERNAL_NET`, nên áp dụng được cho nguồn nội bộ. Ngưỡng 10 thấp hơn giá trị nhỏ nhất quan sát được trên PCAP tấn công (13 gói ICMP ở run5), và cao hơn hẳn giá trị trên lưu lượng bình thường (0).

### 3. Lệnh chạy

```bash
cat $RULES custom-rule-kb02.rules > /tmp/run2_kb02.rules
sudo suricata -T -c /etc/suricata/suricata.yaml -S /tmp/run2_kb02.rules     # successfully loaded
for f in kb02_run*.pcap benign_*.pcap; do
  n=${f%.pcap}; mkdir -p out_kb02/run2/$n
  sudo suricata -c /etc/suricata/suricata.yaml -k none -S /tmp/run2_kb02.rules -r $f -l out_kb02/run2/$n
done
```

![Tạo luật, kiểm tra cú pháp và chạy Run 2](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/10-run2-rule-and-test.png)
*Hình 15. Tạo `custom-rule-kb02.rules`, kiểm tra cú pháp (`successfully loaded`) và chạy Run 2 trên 17 PCAP.*

### 4. Kết quả

| PCAP | 2019102 (ET Open) | 9000201 | 9000202 | Phát hiện |
|---|---|---|---|---|
| run1 (`attack.sh`, 108 s) | – | 2 | 2 | ✅ |
| run2 (T2, 20 cổng) | 1 | 1 | 1 | ✅ |
| run3 (T4, 100 cổng) | 1 | 1 | 1 | ✅ |
| run4 (T4, 200 cổng, 180 s) | – | 3 | 3 | ✅ |
| run5 (10 cổng) | 1 | **–** | 1 | ✅ (chỉ nhờ 9000202) |

![Run 2 – tóm tắt](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/11-run2-summary.png)
*Hình 16. Run 2 trên 12 PCAP bình thường và 5 PCAP KB02 (đã ẩn cảnh báo checksum).*

### 5. Độ trễ phát hiện

Độ trễ được tính từ **gói UDP đầu tiên** của Attacker trong PCAP đến **cảnh báo đầu tiên** của luật nhóm (9000201 hoặc 9000202). Thời gian này bao gồm cả lúc tích lũy đủ ngưỡng 10 gói.

| PCAP | Gói quét đầu tiên | Cảnh báo đầu tiên | SID | Độ trễ |
|---|---|---|---|---|
| run1 | 16:38:43.310 | 16:38:46.759 | 9000202 | 3,45 s |
| run2 | 16:42:48.209 | 16:42:52.822 | 9000202 | 4,61 s |
| run3 | 16:47:02.202 | 16:47:04.415 | 9000201 | 2,21 s |
| run4 | 16:49:06.913 | 16:49:06.913 | 9000201 | < 0,01 s |
| run5 | 16:53:26.042 | 16:53:30.457 | 9000202 | 4,42 s |
| **Trung bình** | | | | **≈ 2,94 s** |

![Bằng chứng và độ trễ](https://raw.githubusercontent.com/phanyen206/Suricata/main/scenarios/02-nmap-udp-scan/screenshots/12-evidence-and-latency.png)
*Hình 17. Số dòng các file trích sự kiện, thời điểm gói quét đầu tiên và thời điểm các cảnh báo (ngày 03/11/2026, đồng hồ Victim).*

Nhận xét:
- Số cảnh báo của mỗi luật gần như tỉ lệ với **thời gian quét**: 1 lần ở các lần quét ngắn, 2 lần ở run1 (108 s), 3 lần ở run4 (180 s). Nguyên nhân là `threshold` giới hạn số lần cảnh báo theo cửa sổ 60 giây, nên **số cảnh báo không phản ánh số cổng bị quét**.
- Ở run4, hai cảnh báo 9000201 đầu tiên chỉ cách nhau khoảng 3,3 giây, ít hơn cửa sổ 60 giây của `threshold`. Nguyên nhân **chưa được xác minh**, có thể liên quan đến cách Suricata xử lý `threshold` khi chạy đa luồng ở chế độ đọc PCAP. Điểm này không ảnh hưởng đến kết luận phát hiện / không phát hiện.

---

## Phần VI – Kiểm tra cảnh báo trên lưu lượng bình thường

| PCAP | Tổng cảnh báo Run 2 | 9000201 | 9000202 | Cảnh báo khác |
|---|---|---|---|---|
| benign_01, benign_02 (ping) | 0 | 0 | 0 | – |
| benign_03 → benign_05 (web) | 177 / 147 / 512 | 0 | 0 | 2034636, checksum |
| benign_06 (20 truy vấn DNS) | 20 | **0** | **0** | checksum UDP |
| benign_07, benign_08 (SSH, SCP) | 24 / 554 | 0 | 0 | checksum |
| benign_09 → benign_11 (kết hợp, có DNS) | 72 / 95 / 457 | **0** | **0** | 2034636, checksum |
| benign_12 (120 request curl) | 721 | 0 | 0 | 2034636, checksum |

- **Không có cảnh báo 9000201/9000202** trên 12 PCAP bình thường, kể cả các file có truy vấn DNS (gói UDP có dữ liệu).
- Tổng số cảnh báo trên từng file **bằng đúng Run 1** (KB01), nên luật nhóm không sinh thêm cảnh báo nào trên lưu lượng bình thường.
- SID 2034636 (Python SimpleHTTP ServerBanner) là luật thông tin của ET Open, và 2200074/2200075 là lỗi checksum. Cả hai đều đã được phân tích ở KB01.

---

## Phần VII – So sánh và đánh giá

| Tiêu chí | Run 1 (ET Open) | Run 2 (ET Open + 9000201/9000202) |
|---|---|---|
| Phát hiện 5 lần quét | **3/5** | **5/5** |
| Phát hiện lần quét theo `attack.sh` (run1) | Không | Có |
| Cơ sở phát hiện | Gói SSDP tới cổng 1900 (phụ thuộc cổng) | Hành vi quét: UDP rỗng hàng loạt, ICMP port unreachable hàng loạt |
| Đúng cặp máy Attacker / Victim | Đúng (3 lần có cảnh báo) | Đúng cả 5 |
| Cảnh báo sai trên 12 PCAP bình thường | 0 | **0** |
| Độ trễ trung bình | – | ≈ 2,94 s |
| **Kết luận theo tiêu chí** | **Chưa đạt** | **Đạt** |

---

## Phần VIII – Hạn chế

1. **Luật 9000202 phụ thuộc vào việc Victim trả ICMP.** Nếu máy chủ có tường lửa chặn ICMP gửi ra, hoặc giới hạn ICMP chặt hơn, luật này có thể không kích hoạt. Khi đó chỉ còn 9000201, và 9000201 bỏ sót trường hợp chỉ quét các cổng dịch vụ có dữ liệu riêng (như run5).
2. **Luật 9000201 dựa vào gói UDP rỗng**, là hành vi mặc định của nmap với các cổng không có dữ liệu riêng. Công cụ quét gửi dữ liệu cho mọi cổng sẽ không bị luật này phát hiện.
3. **Bộ lưu lượng bình thường** chưa có các ứng dụng UDP khác như NTP, SNMP, VoIP, game, hay mDNS từ nhiều máy, và chưa có tình huống hợp lệ sinh nhiều ICMP port unreachable (ví dụ ứng dụng gửi tới cổng đã đóng). Đánh giá cảnh báo sai chỉ đúng trong phạm vi 12 PCAP này.
4. Môi trường chỉ có 2 máy ảo; Suricata chạy ngoại tuyến trên PCAP. Dịch vụ suricata (systemd) trên Victim đang `failed` (xem KB01).
5. `threshold` khiến số cảnh báo phụ thuộc vào thời gian quét. Một trường hợp ở run4 có hai cảnh báo cách nhau ít hơn 60 giây, nguyên nhân chưa xác minh.
6. Đồng hồ Attacker và Victim lệch nhau khoảng 2 phút do đặt giờ bằng tay. Mọi phân tích thời gian đều dùng đồng hồ Victim.
7. Run 1 trên lưu lượng bình thường dùng lại kết quả KB01 (cùng cấu hình), không chạy lại.

---

## Phần IX – Kết luận

- ET Open mặc định **không có luật nhận diện chung cho quét UDP**. Nó chỉ phát hiện được **3/5** lần quét nhờ một luật SSDP (SID 2019102), và kết quả phụ thuộc vào số gói nmap gửi tới cổng 1900. Lần quét theo đúng `attack.sh` không bị phát hiện.
- Hai luật nhóm **9000201** (nhiều gói UDP rỗng) và **9000202** (nhiều ICMP port unreachable) bổ trợ cho nhau. Chúng phát hiện **5/5** lần quét ở các tốc độ (T2, T3, T4) và dải cổng khác nhau (10 đến 200 cổng), với **độ trễ trung bình khoảng 2,9 giây**, và **không có cảnh báo sai** trên 12 PCAP lưu lượng bình thường.
- Kết luận chỉ có giá trị trong phạm vi môi trường và dữ liệu đã kiểm thử, với các hạn chế nêu ở Phần VIII.

---

## Danh sách file trong thư mục

| File | Nội dung |
|---|---|
| `README.md` | Báo cáo kịch bản (file này) |
| `attack.sh` | Lệnh tấn công gốc (`nmap -sU --top-ports 100`) |
| `lenh_attacker_victim.txt` | Lệnh thực tế đã chạy và số liệu từng lần quét |
| `custom-rule.rules` | Luật nhóm SID 9000201, 9000202 |
| `kb02_run1.pcap` … `kb02_run5.pcap` | 5 PCAP tấn công (run1 tương ứng `attack.sh`) |
| `eve-excerpt-run1.json` | Run 1: toàn bộ cảnh báo trên 5 PCAP (18 dòng: 3 × 2019102, 15 × checksum) |
| `eve-excerpt-run2.json` | Run 2: cảnh báo 9000201, 9000202, 2019102 (18 dòng) |
| `benign-eve-excerpt-run1.json` | Run 1 trên lưu lượng bình thường, dùng lại từ KB01 (223 dòng, đều là SID 2034636) |
| `benign-eve-excerpt-run2.json` | Run 2 trên lưu lượng bình thường, đã lọc checksum (223 dòng, đều là SID 2034636) |
| `summary-run1.txt`, `summary-run2.txt` | Bảng tóm tắt cảnh báo |
| `screenshots/` | Ảnh minh chứng |


## Tệp nguồn và minh chứng gốc

Thư mục nguồn trong repository ban đầu: [`02-nmap-udp-scan`](https://github.com/phanyen206/Suricata/tree/main/scenarios/02-nmap-udp-scan). Các tệp nhị phân như PCAP, ảnh chụp và tài liệu DOCX (nếu có) hiện vẫn được giữ tại repository nguồn; README này liên kết về nguồn để người đọc tải/xem, không thay thế bằng dữ liệu giả.
