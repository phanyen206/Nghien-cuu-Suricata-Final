> **Hướng dẫn người đọc:** README này mô tả mục tiêu, môi trường, thứ tự tái lập và cách kiểm tra kết quả. Hãy đọc phần môi trường và lệnh trước khi chạy script; cập nhật IP/interface theo lab của bạn. Chỉ chạy trong mạng ảo được phép.

<img width="981" height="214" alt="image" src="https://github.com/user-attachments/assets/76717ff3-0d77-4cbf-b64b-489f6f7139b0" /># KỊCH BẢN 13 — SQL Injection: ET Open vs ET Open + Custom Rules

**Trạng thái:** Run 1, Run 2 và thử nghiệm benign đã thực hiện và xác minh qua ảnh; độ trễ cảnh báo thời gian thực **chưa đo**.

> Lab có kiểm soát trên hai máy ảo Ubuntu. Trang đích Apache `/index.html` là HTML tĩnh: HTTP 200 chứng minh request được phục vụ, **không** chứng minh khai thác SQLi đối với CSDL.

## 1. Nguồn yêu cầu và phạm vi

Đối chiếu `scenarios/13-sql-injection/README.md`, `attack.sh`, tài liệu Word *Kịch bản 13* trong ZIP gốc: (i) Python `urllib` gửi hai payload, kiểm tra HTTP 200; (ii) ET Open baseline Run 1; (iii) SID tự viết 1000008/1000018 Run 2; (iv) đối chiếu cảnh báo, false positive và độ trễ. README gốc để trống ngưỡng thành công và chưa có thời gian phát hiện; báo cáo không tự tạo số liệu này.

| Vai trò | IP | NIC | Thành phần |
|---|---|---|---|
| Attacker | `192.168.100.10/24` | `enp0s3` | curl, Python3 |
| Victim | `192.168.100.20/24` | `enp0s3` | Apache 2.4.66, Suricata 8.0.3, ET Open |

Suricata Victim: `HOME_NET: "[192.168.100.20/32]"`, `EXTERNAL_NET: "!$HOME_NET"`. Đây là **biến phân loại trong Suricata**, NIC thật vẫn `/24`. IP nguồn có lúc tự đổi do DHCP; cần xác minh `ip -br addr` trước khi tái hiện.

## 2. Bài toán thực tế và giả thuyết

Một web app có tham số truy vấn `id` có thể bị thăm dò bằng Boolean tautology (`1' OR '1'='1`) và UNION SELECT (`1 UNION SELECT 1,2`). Lab dùng web tĩnh để tạo luồng HTTP có dấu hiệu SQLi, đánh giá **IDS signature matching**, không thực thi SQL trong CSDL.

**Giả thuyết:** Luật ET Open được bật sẵn có thể không khớp hai request mô phỏng. Bổ sung hai signature nhắm đúng mẫu URI giúp cảnh báo, nhưng có thể không bao phủ biến thể và phải kiểm tra false positive.

## 3. Chuẩn bị và xác minh

**Victim:**

```bash
ip -br addr
sudo systemctl status apache2 --no-pager
suricata -V
sudo ls -lh /var/lib/suricata/rules/suricata.rules
sudo grep -n -E 'HOME_NET:|EXTERNAL_NET:' /etc/suricata/suricata.yaml | head -10
sudo suricata -T -c /etc/suricata/suricata.yaml -S /var/lib/suricata/rules/suricata.rules
curl -I http://192.168.100.20/index.html
```
<img width="903" height="291" alt="image" src="https://github.com/user-attachments/assets/f35ae9c1-3c88-4d84-8646-02c3281a0097" />



<img width="718" height="291" alt="image" src="https://github.com/user-attachments/assets/74fcaaca-2007-4133-9b84-d468fa2e4dd7" />



<img width="671" height="297" alt="image" src="https://github.com/user-attachments/assets/0f993568-4fc3-4ebb-a691-62f3072b0bde" />



**Attacker:** `ip -br addr; ping -c 4 192.168.100.20`. Khi dùng VirtualBox, NIC thật của lab là `enp0s3` (không thay bằng `ens33` trừ khi máy khác có NIC đó).

## 4. Payload và script Python `urllib`

Tài liệu gốc có `attack.sh` kiểu `curl -G`; nội dung sau đáp ứng riêng yêu cầu Python `urllib` của file Word. Trên Attacker tạo `~/Suricata/scenarios/13-sql-injection/attack.sh` rồi `chmod +x attack.sh`.

```bash
#!/bin/bash
set -e
python3 - <<'PYCODE'
import urllib.parse
import urllib.request
import urllib.error
base = 'http://192.168.100.20/index.html'
print('Dang chay kich ban gia lap SQL Injection...')
for i, payload in enumerate(["1' OR '1'='1", '1 UNION SELECT 1,2'], 1):
    url = base + '?' + urllib.parse.urlencode({'id': payload})
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            print(f'Payload {i} status: {r.status}')
            print(f'URL: {url}')
    except Exception as e:
        print(f'Payload {i} failed: {e}')
print('Da hoan tat gui request kiem thu.')
PYCODE
```

<img width="819" height="188" alt="image" src="https://github.com/user-attachments/assets/630a38be-5e74-486c-9f56-c02976d48f8b" />


**Cách chạy:** `chmod +x attack.sh && ./attack.sh`; yêu cầu kỳ vọng `Payload 1 status: 200` và `Payload 2 status: 200`. Trong bằng chứng phiên này, `curl` và PCAP đã xác nhận hai URI HTTP; **không có ảnh terminal chứng minh script Python trên đã được chạy**, nên không đánh dấu mục Python đã kiểm chứng.

## 5. Run 1 — ET Open nguyên bản (chưa custom)

Trên Victim bắt PCAP (giữ terminal mở):

```bash
sudo mkdir -p /opt/scenario13/run1
sudo tcpdump -i enp0s3 -s 0 -nn -w /opt/scenario13/sqli-test.pcap 'host 192.168.100.10 and tcp port 80'
```

<img width="756" height="133" alt="image" src="https://github.com/user-attachments/assets/9a0c1524-dab7-4af1-b8c9-3405afcc4ded" />


Trên Attacker gửi hai mẫu bằng curl (đúng dữ liệu đã thấy trong PCAP):

```bash
curl -G 'http://192.168.100.20/index.html' --data-urlencode "id=1' OR '1'='1"
curl -G 'http://192.168.100.20/index.html' --data-urlencode 'id=1 UNION SELECT 1,2'
```

<img width="997" height="244" alt="image" src="https://github.com/user-attachments/assets/b02b656e-c37d-4d39-b04e-0b7cfda35a62" />

![Uploa<img width="981" height="214" alt="image" src="https://github.com/user-attachments/assets/2985d903-c4f9-4599-b6ed-00c656577ae7" />
ding image.png…]()



Dừng tcpdump bằng `Ctrl+C`, rồi phân tích offline **chỉ ET Open**:

```bash
sudo suricata -c /etc/suricata/suricata.yaml -r /opt/scenario13/sqli-test.pcap -S /var/lib/suricata/rules/suricata.rules -l /opt/scenario13/run1 -k none
sudo jq -r 'select(.event_type=="http") | [.src_ip,.dest_ip,.http.url] | @tsv' /opt/scenario13/run1/eve.json
sudo jq -r 'select(.event_type=="alert") | [.alert.signature_id,.alert.signature] | @tsv' /opt/scenario13/run1/eve.json | sort | uniq -c
```

<img width="955" height="219" alt="image" src="https://github.com/user-attachments/assets/8468e113-b374-4a04-9006-1073d15bde91" />


**Quan sát thực:** PCAP có hai HTTP GET; Suricata có hai sự kiện HTTP. Không thấy alert SQLi của ET Open. SID `2200074` là cảnh báo engine `SURICATA TCPv4 invalid checksum`, **không được ghi là ET Open bắt SQLi**. Các dòng SQLi trong file rules được kiểm tra mẫu có dấu `#` (comment); không khẳng định mọi SQLi rule của ET Open đều vô hiệu.

## 6. Run 2 — ET Open cộng hai luật tự viết

Trên Victim tạo `/opt/scenario13/custom-sqli.rules` **mỗi rule một dòng**:

```suricata
alert http 192.168.100.10 any -> 192.168.100.20 80 (msg:"LOCAL SQLi Boolean OR Detection"; flow:established,to_server; http.uri.raw; content:"%27+OR+"; nocase; sid:1000008; rev:1;)
alert http 192.168.100.10 any -> 192.168.100.20 80 (msg:"LOCAL SQLi UNION SELECT Detection"; flow:established,to_server; http.uri.raw; content:"+UNION+SELECT+"; nocase; sid:1000018; rev:1;)
```
<img width="980" height="187" alt="image" src="https://github.com/user-attachments/assets/5dfc1255-3988-414a-a96a-533ebc3bd1c3" />



**Giải thích:** `alert http`: cảnh báo trên HTTP; `192.168.100.10 any -> 192.168.100.20 80`: hướng Attacker đến web Victim; `flow:established,to_server`: luồng TCP đã thiết lập gửi tới server; `http.uri.raw`: so khớp URI HTTP mã hóa thô; `content` là chuỗi byte cần khớp; `nocase` bỏ qua hoa/thường; `sid` là ID custom; `rev` bản sửa. `%27` là dấu `'` mã hóa URL, dấu `+` tượng trưng khoảng trắng theo form encoding. Luật này cố ý đặc thù, dễ bỏ sót biến thể dùng `%20`, encoding khác, body POST, hoặc khác IP/port.

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -S /opt/scenario13/custom-sqli.rules
sudo sh -c 'cat /var/lib/suricata/rules/suricata.rules /opt/scenario13/custom-sqli.rules > /opt/scenario13/combined.rules'
sudo suricata -T -c /etc/suricata/suricata.yaml -S /opt/scenario13/combined.rules
sudo mkdir -p /opt/scenario13/run2
sudo suricata -c /etc/suricata/suricata.yaml -r /opt/scenario13/sqli-test.pcap -S /opt/scenario13/combined.rules -l /opt/scenario13/run2 -k none
sudo jq -r 'select(.event_type=="alert") | [.alert.signature_id,.alert.signature] | @tsv' /opt/scenario13/run2/eve.json | sort | uniq -c
```
<img width="971" height="456" alt="image" src="https://github.com/user-attachments/assets/176dac25-60b5-441e-8802-1ddbf53a7bdb" />

*


**Quan sát thực:** `1000008` = 1 alert; `1000018` = 1 alert; `2200074` = 22 alerts. Suricata đọc 37 packets / 24,554 bytes của tệp tấn công. Hai cảnh báo SQLi đến từ custom rules, không phải ET Open gốc.

## 7. Kiểm tra false positive

Victim bắt riêng PCAP lành tính:

```bash
sudo tcpdump -i enp0s3 -s 0 -nn -w /opt/scenario13/benign.pcap 'host 192.168.100.10 and tcp port 80'
```

<img width="747" height="129" alt="image" src="https://github.com/user-attachments/assets/80fdf5f6-9595-4e96-bc6e-be77c35c949f" />


Attacker gửi bốn GET và dừng tcpdump bằng Ctrl+C:

```bash
curl 'http://192.168.100.20/index.html'
curl 'http://192.168.100.20/index.html?id=123'
curl 'http://192.168.100.20/index.html?name=student'
curl 'http://192.168.100.20/index.html?id=2026'
```

```bash
sudo mkdir -p /opt/scenario13/benign
sudo suricata -c /etc/suricata/suricata.yaml -r /opt/scenario13/benign.pcap -S /opt/scenario13/combined.rules -l /opt/scenario13/benign -k none
sudo jq -s '[.[] | select(.event_type=="alert") | select(.alert.signature_id==1000008 or .alert.signature_id==1000018)] | length' /opt/scenario13/benign/eve.json
```

<img width="638" height="339" alt="image" src="https://github.com/user-attachments/assets/77a5eb85-8a07-4ff1-8de1-acf1c0c8b834" />



**Kết quả quan sát:** 4 GET hợp lệ trong PCAP, tổng 83 packets / 49,990 bytes được Suricata xử lý; kết quả đếm **0** cảnh báo từ hai SID custom. Đây là **0/4 mẫu benign**, không phải cam kết false positive bằng 0 ngoài đời thực.

## 8. Đối chiếu thực nghiệm

| Chỉ tiêu | Run 1 — ET Open | Run 2 — ET Open + Custom |
|---|---|---|
| Boolean SQLi, mẫu 1 | 0 alert SQLi | 1 alert, SID 1000008 |
| UNION SELECT, mẫu 2 | 0 alert SQLi | 1 alert, SID 1000018 |
| Tỷ lệ nhận diện trên **2 mẫu đã chọn** | 0/2 | 2/2 |
| Decoder checksum | Có SID 2200074 | Có SID 2200074 (22 lần) |
| Benign 4 GET | Chưa đo riêng bằng ET Open | 0 custom alerts |
| Độ trễ phát hiện | **Chưa đo** | **Chưa đo** |

**Độ trễ:** Đang phân tích PCAP offline, thời gian log không đồng nghĩa độ trễ engine real-time. Nếu tài liệu chấm chỉ tiêu này, cần chạy live IDS, đồng bộ thời gian và đo điểm phát sinh request/điểm alert theo phương pháp cố định. Không tự suy ra giá trị từ timestamp trong PCAP.

## 10. Hạn chế và lưu ý tái hiện

- Mẫu thử chỉ gồm hai GET trên Apache tĩnh; chưa thử SQL engine, các biến thể encoding, POST hoặc rule performance.
- Quy tắc dành riêng IP `.10` và `.20`, cổng `80`, nên cần sửa nếu khác môi trường.
- DHCP từng làm Attacker quay về `.4`, Victim về `.3`; phải cấu hình IP ổn định trước khi chạy lại, tránh gán chồng IP.
- `2200074` có thể xuất phát từ checksum/offloading trong máy ảo; không đánh đồng với ET Open SQLi alerts.
- Thử nghiệm chỉ được phép chạy trong lab thuộc quyền kiểm soát.

## 11. Tài liệu gốc

- `Suricata-main/scenarios/13-sql-injection/README.md` trong ZIP do người học cung cấp.
- `Suricata-main/scenarios/13-sql-injection/attack.sh` trong ZIP do người học cung cấp.
- `Suricata-main/scenarios/13-sql-injection/Kịch bản13.docx` (tên trong ZIP có lỗi mã hóa), nội dung yêu cầu Python urllib và HTTP status.
- Bằng chứng là ảnh terminal người học cung cấp trong phiên thực nghiệm ngày 01/11/2026.


---

## 12. HƯỚNG DẪN CHỤP ẢNH THEO MÁY (bản thực hành chi tiết)

**Quy ước KHÔNG ĐƯỢC ĐẢO IP:** `ATTACKER=192.168.100.10/24` (Ubuntu gửi payload), `VICTIM=192.168.100.20/24` (Apache + Suricata). Card mạng thực tế của cả hai là `enp0s3`. `HOME_NET=192.168.100.20/32` chỉ là phân loại Suricata trên Victim, không phải IP/subnet của Ubuntu. Trong file Word gốc Attacker từng ghi `10.0.2.10`; đó không phải IP đã dùng trong buổi thực nghiệm.

### Bảng ảnh theo đúng terminal, lệnh và vị trí chèn

| Ảnh | Chạy/chụp trên máy | Dòng lệnh hoặc nội dung bắt buộc phải nhìn thấy | Vị trí chèn Word | Tình trạng |
|---|---|---|---|---|
| 01 | **ATTACKER .10** | `ip -br addr`, `ping -c 4 192.168.100.20`, 0% loss | Môi trường | Đã có |
| 02 | **VICTIM .20** | `ip -br addr`, `curl -I http://192.168.100.20/index.html` | Môi trường | Đã có thành phần, có thể chụp gộp |
| 03 | **VICTIM .20** | `HOME_NET: "[192.168.100.20/32]"`, `suricata -T` hợp lệ | Cấu hình IDS | Đã có |
| 04 | **ATTACKER .10** | `./attack_urllib.sh` và `Payload 1 status: 200`, `Payload 2 status: 200` | **Ngay sau đoạn Python urllib** | **Chưa có, phải chụp bổ sung** |
| 05 | **ATTACKER .10** | Hai lệnh `curl -G ... --data-urlencode ...` | Sinh tải SQLi | Nên chụp bổ sung nếu cần ảnh từng máy |
| 06 | **VICTIM .20** | `tcpdump -A ... sqli-test.pcap`, hai `GET` SQLi | Run 1 | Đã có |
| 07 | **VICTIM .20** | `jq` đọc HTTP và cảnh báo Run 1; không có alert SQLi | Cuối Run 1 | Đã có |
| 08 | **VICTIM .20** | `cat /opt/scenario13/custom-sqli.rules`, hai SID 1000008/1000018 | Trước giải thích rule | Đã có ảnh kết hợp |
| 09 | **VICTIM .20** | `suricata -T ...combined.rules` hợp lệ | Trước chạy Run 2 | Đã có |
| 10 | **VICTIM .20** | `jq ... run2/eve.json`: 1 alert/SID custom | Cuối Run 2 | Đã có |
| 11 | **VICTIM .20** | `tcpdump ... benign.pcap`, bốn GET bình thường | Kiểm tra benign | Đã có |
| 12 | **VICTIM .20** | `jq ...benign/eve.json` trả về `0` | Cuối kiểm tra false positive | Đã có |

### Python urllib ở đâu và chạy như thế nào?

**Chạy DUY NHẤT trên ATTACKER `.10`**. Python tạo HTTP GET đến **VICTIM `.20` cổng 80**. Script trong Word gốc được yêu cầu, nhưng ảnh thực nghiệm trước đó mới chứng minh lệnh `curl`. Để chụp ảnh riêng cho yêu cầu `urllib`, tạo file **`attack_urllib.sh`** (tên tách biệt `attack.sh` curl từ ZIP gốc):

```bash
# ATTACKER 192.168.100.10
mkdir -p ~/Suricata/scenarios/13-sql-injection
cd ~/Suricata/scenarios/13-sql-injection
nano attack_urllib.sh
```

Dán code đầy đủ:

```bash
#!/bin/bash
set -e
python3 - <<'PYCODE'
import urllib.parse
import urllib.request
import urllib.error
base = 'http://192.168.100.20/index.html'
payloads = ["1' OR '1'='1", '1 UNION SELECT 1,2']
print('Dang chay kich ban gia lap SQL Injection...')
for i, payload in enumerate(payloads, 1):
    url = base + '?' + urllib.parse.urlencode({'id': payload})
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            print(f'Payload {i}: {payload}')
            print(f'URL: {url}')
            print(f'Payload {i} status: {response.status}')
    except Exception as exc:
        print(f'Payload {i} failed: {exc}')
print('Da hoan tat gui request kiem thu.')
PYCODE
```

Chạy trên **ATTACKER**:

```bash
chmod +x attack_urllib.sh
bash -n attack_urllib.sh
./attack_urllib.sh
```

**Chụp Ảnh 04 ngay sau khi script chạy thành công**: cần thấy dòng `./attack_urllib.sh`, 2 `URL` trỏ tới `192.168.100.20`, 2 status `200`. Đặt ở mục **“Payload và script Python urllib”** trong báo cáo. Nếu chưa chạy, chỉ ghi *“Code được cung cấp để tái hiện; chưa có ảnh xác nhận thực thi”*. Status 200 **không chứng minh khai thác SQL thành công** trên Apache tĩnh.

### Nhãn từng máy khi tái hiện đầy đủ

**VICTIM .20, cửa sổ 1 – bật bắt gói Run 1:**

```bash
sudo mkdir -p /opt/scenario13/run1
sudo tcpdump -i enp0s3 -s 0 -nn -w /opt/scenario13/sqli-test.pcap 'host 192.168.100.10 and tcp port 80'
```

**ATTACKER .10 – gửi mẫu SQLi Run 1:**

```bash
curl -G 'http://192.168.100.20/index.html' --data-urlencode "id=1' OR '1'='1"
curl -G 'http://192.168.100.20/index.html' --data-urlencode 'id=1 UNION SELECT 1,2'
```

**VICTIM .20 – Ctrl+C ở cửa sổ tcpdump, phân tích ET Open nguyên bản:**

```bash
sudo tcpdump -A -nn -r /opt/scenario13/sqli-test.pcap 'tcp dst port 80' | grep 'GET '
sudo suricata -c /etc/suricata/suricata.yaml -r /opt/scenario13/sqli-test.pcap -S /var/lib/suricata/rules/suricata.rules -l /opt/scenario13/run1 -k none
sudo jq -r 'select(.event_type=="http") | [.src_ip,.dest_ip,.http.url] | @tsv' /opt/scenario13/run1/eve.json
sudo jq -r 'select(.event_type=="alert") | [.alert.signature_id,.alert.signature] | @tsv' /opt/scenario13/run1/eve.json | sort | uniq -c
```

**VICTIM .20 – Run 2:** dùng hai luật đã ghi tại mục 6, tạo `combined.rules` và phân tích **cùng file** `sqli-test.pcap`. Kết quả đã quan sát `1000008=1`, `1000018=1`, `2200074=22`. Không nhận SID 2200074 là dấu hiệu ET Open phát hiện SQLi.

**VICTIM .20 – bắt gói benign** và **ATTACKER .10 – gửi bốn lệnh curl bình thường**: xem đầy đủ mã tại mục 7. Ở cuối mục 7, chụp kết quả `0` của hai SID custom. Kết luận chỉ giới hạn trên 4 request đã dùng.

**Lưu ý khi upload GitHub:** Ảnh đã chèn vào DOCX không tự xuất hiện trong README. Hãy upload `scenario13-evidence.png` cạnh `README.md`, hoặc tạo thư mục `images/` với ảnh PNG và đường dẫn Markdown tương ứng. Không bắt buộc ZIP. Dữ liệu trễ cảnh báo real-time vẫn *chưa đo*.


## Tệp nguồn và minh chứng gốc

Thư mục nguồn trong repository ban đầu: [`13-sql-injection`](https://github.com/phanyen206/Suricata/tree/main/scenarios/13-sql-injection). Các tệp nhị phân như PCAP, ảnh chụp, gói minh chứng hoặc tài liệu DOCX (nếu có) hiện vẫn được giữ tại repository nguồn; README này liên kết về nguồn để người đọc tải/xem, không thay thế bằng dữ liệu giả.
