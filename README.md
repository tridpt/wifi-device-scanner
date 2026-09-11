# 📡 Wi-Fi Device Scanner (Ứng dụng Quản lý & Quét thiết bị Wi-Fi)

Ứng dụng Desktop hiện đại cho Windows giúp kiểm tra chính xác **có bao nhiêu thiết bị đang dùng chung mạng Wi-Fi**, hiển thị đầy đủ thông tin: Địa chỉ IP, Địa chỉ MAC, Tên máy (Hostname), và Nhà sản xuất thiết bị (Apple, Samsung, TP-Link, Xiaomi, ZTE, v.v.).

---

## 🌟 Các tính năng nổi bật

1. **Quét siêu tốc với Windows Native C-API & Nhận diện Subnet động**:
   - Sử dụng trực tiếp hàm `SendARP` từ `iphlpapi.dll` của Windows với kiến trúc đa luồng cực nhanh.
   - **Tự động nhận diện Subnet Mask thực tế**: Tự động phát hiện dải mạng thực tế (`/24`, `/23`, `/22`...) qua `ipconfig` và mô-đun `ipaddress`, không bị giới hạn cứng ở dải 254 host.
   - **Không cần cài driver ngoài** (không cần WinPcap / Npcap / Wireshark).
   - **Không cần quyền Administrator** (Zero UAC).
   - **Vượt qua tường lửa ICMP trên Host**: Tận dụng cơ chế bắt buộc của giao thức ARP ở tầng Liên kết dữ liệu (Layer 2) để phát hiện các thiết bị chặn ICMP ping trong cùng Broadcast Domain. *(Lưu ý: Không áp dụng nếu Access Point bật Client/AP Isolation, qua các VLAN phân tách, hoặc thiết bị di động ở trạng thái ngủ sâu DTIM)*.
2. **Nhận diện thông minh**:
   - Tự động nhận diện Router Wi-Fi / Gateway mặc định và Đánh dấu "ROUTER / MODEM".
   - Đánh dấu máy tính bạn đang sử dụng ("MÁY NÀY").
   - Tra cứu hơn 200+ thương hiệu thiết bị phần cứng từ OUI MAC.
   - Phát hiện **Địa chỉ MAC ngẫu nhiên (Private MAC)** theo chuẩn IEEE 802 (tính năng bảo mật trên iPhone iOS 14+, Android 10+, Windows 11).
3. **Giao diện người dùng hiện đại (CustomTkinter)**:
   - Hỗ trợ chế độ Dark Mode / Light Mode.
   - Cập nhật thời gian thực (Live streaming UI) khi từng thiết bị được tìm thấy.
   - Thanh tìm kiếm và bộ lọc nhanh theo IP, MAC, Tên máy, Hãng sản xuất.
   - Nút copy nhanh IP / MAC và nút vào trang quản trị modem 1 chạm.
4. **Trình Đổi Danh Tính Card Mạng (MAC Address Randomizer / MAC Spoofing)**:
   - Đổi ngẫu nhiên địa chỉ MAC Wi-Fi trên adapter do bạn sở hữu/quản trị (Zero UAC khi Windows cho phép).
   - Hỗ trợ khôi phục cấu hình và hướng dẫn xử lý DHCP/captive portal theo chính sách của quản trị viên.
   - Không dùng để né captive portal, khóa truy cập, thanh toán hoặc cơ chế kiểm soát của mạng khác.
5. **Soi Luồng Video Camera & Kiểm Tra Khóa Mật Khẩu (RTSP Streamer & Auth Checker)**:
   - Dò luồng RTSP camera theo từng hãng (Hikvision, Dahua, Imou, Tapo, Yoosee, Tuya) và mở xem trực tiếp bằng VLC Player.
   - Kiểm tra xem camera có đang được bảo vệ bằng mật khẩu (401 Unauthorized) hay bị mở toang (200 OK).
6. **Biểu đồ Ping thời gian thực & Chẩn đoán thông minh (Ping Graph)**:
   - Đo độ trễ kép Router LAN & Internet WAN, xác định nguyên nhân lag do sóng yếu hay do nhà mạng cáp quang.
   - **Cơ chế Hybrid Smart Ping**: Tự động chuyển đổi giữa ICMP ping và TCP SYN/ACK (Port 53/80/443) khi gặp tường lửa nhà mạng hoặc router chặn gói tin ICMP, loại bỏ tình trạng báo 100% Packet Loss sai lệch.
7. **Bật máy tính từ xa (Wake-on-LAN - WoL)**:
   - Đánh thức máy tính qua mạng bằng gói tin AMD Magic Packet.
8. **Sơ đồ mạng tương tác trực quan (Interactive Network Topology Map)**:
   - Bản đồ đồ họa Canvas hiển thị Router trung tâm tỏa sóng Wi-Fi ra toàn bộ thiết bị.
   - Hỗ trợ **kéo thả chuột di chuyển node tự do**, đường dây liên kết co giãn theo thời gian thực.
   - Bấm vào thiết bị để bung thẻ thông tin chi tiết (IP, MAC, Hãng, RTT) và thao tác nhanh (Soi cổng, Chặn MAC, WoL).
9. **Trình Dò Ổ Đĩa Chia Sẻ Mạng LAN & Thư Mục SMB (SMB Shared Folders & NAS Explorer)**:
   - Dò tìm các máy tính Windows, máy chủ, ổ cứng mạng NAS, và Router chia sẻ dữ liệu qua giao thức SMB (Cổng 445/139).
   - Tự động trích xuất danh sách thư mục chia sẻ công khai (`Users`, `Public`, `Media`, `Data`...).
   - **Phân loại mức độ rủi ro**: Nhận diện thư mục mở toang không cần mật khẩu (`🚨 CÔNG KHAI`) và các máy có bảo mật mật khẩu (`🔒 CẦN ĐĂNG NHẬP`).
   - **1-Click mở Windows File Explorer**: Mở thẳng thư mục mạng hoặc thư mục gốc `\\192.168.1.xxx` trên máy tính.
   - **Soi máy tính của bạn (This PC)**: Phát hiện xem máy bạn có đang vô tình share thư mục nào ra Wi-Fi công cộng không, kèm nút mở nhanh `fsmgmt.msc` để thu hồi chia sẻ.
10. **Đồng Hồ Đo Tốc Độ Băng Thông LAN (LAN Speedtest Tachometer Gauge 0-1000+ Mbps)**:
   - Mặt đồng hồ kim tua máy xe đua thể thao (Racing Tachometer) hoạt họa 60 FPS mượt mà.
   - Đo tốc độ liên kết vô tuyến phần cứng (Receive/Transmit Rate) từ card Wi-Fi, sóng % và RSSI dBm.
   - Đo độ trễ cực nhanh và độ trồi sụt Jitter tới Router Gateway (`192.168.1.1`).
   - Hoàn toàn **không tiêu tốn dung lượng Internet / 4G**, hỗ trợ chẩn đoán chính xác vị trí bắt sóng Wi-Fi trong nhà.
11. **Trình Phân Tích Phổ Kênh Sóng Wi-Fi (Wi-Fi Channel Analyzer & Spectrum Graph)**:
   - Đồ họa Canvas phổ sóng hình chuông (Bell Curve Parabolic Graph) trực quan cho cả 2 băng tần **2.4 GHz** và **5 GHz**.
   - Quét toàn bộ mạng Wi-Fi và BSSID nhà hàng xóm, nhận diện can nhiễu đồng kênh (Co-Channel) và kênh kề.
   - **Tự động xếp hạng & đề xuất kênh tối ưu (Smart Channel Rating)**: Đánh giá mật độ phân bổ và chỉ ra kênh sạch nhất (1, 6, 11 trên 2.4 GHz hoặc 36, 40, 44... trên 5 GHz) để đổi trên Router.
   - Tương tác rê chuột (Hover Tooltip): Hiển thị tên mạng, BSSID, Hãng sản xuất modem qua MAC OUI, Cường độ sóng và mức chiếm dụng kênh.

12. **Lịch sử mạng & cảnh báo thay đổi (SQLite)**:
   - Lưu snapshot theo từng lần quét tại `%LOCALAPPDATA%\\WifiDeviceScanner\\history.db`.
   - Phát hiện thiết bị mới, biến mất, đổi IP hoặc đổi MAC; thông báo Windows khi có thay đổi.
   - Cho phép đặt tên, phòng, ghi chú và đánh dấu thiết bị tin cậy. Annotation được giữ lại khi thiết bị đổi IP/MAC nếu có thể ghép nối.
13. **Discovery đa nguồn & độ tin cậy**:
   - Hỗ trợ IPv6 neighbor cache, mDNS, SSDP/UPnP và reverse-DNS/NetBIOS hostname.
   - Chọn nhiều adapter, retry/rate-limit và giới hạn an toàn cho CIDR lớn; hiển thị cảnh báo AP/client isolation hoặc VLAN thay vì khẳng định tuyệt đối.
14. **Security dashboard có bằng chứng**:
   - Kiểm tra SMB guest (negotiate-only, trạng thái guest vẫn ghi `unverified` nếu chưa xác minh), UPnP, Telnet, HTTP/HTTPS quản trị và DNS.
   - Mỗi finding gồm trạng thái, banner/response quan sát được, độ tin cậy và cách khắc phục. Cổng RTSP chỉ được hiển thị là nghi vấn cho tới khi handshake/banner xác minh.
15. **Báo cáo chia sẻ được**:
   - Xuất HTML tự chứa hoặc PDF ngang A4; báo cáo gồm thiết bị, lịch sử, độ phủ quan sát và findings bảo mật.
   - Bộ lọc theo loại thiết bị, phòng và mức rủi ro; chế độ `Quét nhanh`, `Quét đầy đủ`, `Chỉ thiết bị mới`.

---

## 🚀 Hướng dẫn khởi chạy

### Cài đặt lần đầu
Mở PowerShell tại thư mục dự án và chạy:
```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Cách 1: Khởi chạy 1-Click
Nhấp đúp chuột vào tệp:
```
run_scanner.bat
```
hoặc chạy ngầm êm ái bằng `Chay_Scanner.vbs`.

### Cách 2: Khởi chạy bằng lệnh dòng lệnh
Mở Terminal / PowerShell và chạy:
```powershell
.\.venv\Scripts\python.exe .\main.py
```

---

## 📁 Cấu trúc mã nguồn

```
WifiDeviceScanner/
├── main.py                  # Giao diện chính CustomTkinter (Dashboard, Tabs, Cards, Danh sách)
├── wifi_channel_analyzer.py # Trình phân tích phổ kênh sóng Wi-Fi (Bell Curve Spectrum Canvas)
├── lan_speedtest.py         # Đồng hồ đo tốc độ băng thông LAN (Racing Speedometer Gauge 60 FPS)
├── lan_shared_folders.py    # Trình dò ổ đĩa chia sẻ mạng LAN & Thư mục SMB (NetAPI32 Win32 C-API)
├── mac_randomizer.py        # Trình đổi danh tính MAC 1-click (IEEE LAA, Seed Injection)
├── camera_streamer.py       # Soi & phát luồng RTSP Camera qua VLC Media Player
├── camera_auth_checker.py   # Kiểm tra camera có khóa pass hay không (401 vs 200)
├── spy_camera_detector.py   # Quét phát hiện camera giấu kín & còi báo động
├── port_scanner.py          # Bộ soi cổng mở rộng hơn 100+ cổng dịch vụ
├── ping_monitor.py          # Engine đo độ trễ kép & vẽ biểu đồ Canvas
├── security_audit.py        # Đánh giá an ninh mạng Wi-Fi và Router (/100)
├── wake_on_lan.py           # Tiện ích đánh thức máy tính từ xa qua UDP Magic Packet
├── mac_blocker.py           # Trợ lý hướng dẫn chặn MAC trên Modem
├── network_topology.py      # Sơ đồ mạng tương tác trực quan (Canvas Star Topology Map)
├── scanner.py               # Engine quét mạng ARP đa luồng tốc độ cao
├── oui_db.py                # Cơ sở dữ liệu nhận diện hãng sản xuất OUI & MAC bảo mật
├── export_utils.py          # Tiện ích xuất dữ liệu ra file CSV và JSON
├── network_history.py       # SQLite snapshot, annotation và cảnh báo thay đổi
├── network_discovery.py     # IPv6 neighbor, mDNS, SSDP/UPnP và confidence score
├── report_utils.py          # Báo cáo HTML/PDF tự chứa, có bằng chứng/khắc phục
├── notifications.py         # Windows toast notification (fallback an toàn)
└── README.md                # Tài liệu hướng dẫn sử dụng
```
