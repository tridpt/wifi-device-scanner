"""
oui_db.py - Cơ sở dữ liệu nhận diện nhà sản xuất (Vendor) từ địa chỉ MAC.
Bao gồm danh sách hàng trăm nhà sản xuất phổ biến và thuật toán nhận diện
địa chỉ MAC ngẫu nhiên (Private/Randomized MAC) theo chuẩn IEEE 802.
"""

# Bảng tra cứu OUI phổ biến (3 byte đầu tiên của MAC)
# Định dạng: "XX:XX:XX" -> (Tên nhà sản xuất, Gợi ý thiết bị)
OUI_DATABASE = {
    # Apple
    "00:03:93": ("Apple", "Thiết bị Apple (Mac/iPhone)"),
    "00:05:02": ("Apple", "Thiết bị Apple"),
    "00:0A:27": ("Apple", "Thiết bị Apple"),
    "00:0A:95": ("Apple", "Thiết bị Apple"),
    "00:0D:93": ("Apple", "Thiết bị Apple"),
    "00:10:FA": ("Apple", "Thiết bị Apple"),
    "00:11:24": ("Apple", "Thiết bị Apple"),
    "00:14:51": ("Apple", "Thiết bị Apple"),
    "00:16:CB": ("Apple", "Thiết bị Apple"),
    "00:17:F2": ("Apple", "Thiết bị Apple"),
    "00:19:E3": ("Apple", "Thiết bị Apple"),
    "00:1B:63": ("Apple", "Thiết bị Apple"),
    "00:1C:B3": ("Apple", "Thiết bị Apple"),
    "00:1D:4F": ("Apple", "Thiết bị Apple"),
    "00:1E:52": ("Apple", "Thiết bị Apple"),
    "00:1E:C2": ("Apple", "Thiết bị Apple"),
    "00:1F:5B": ("Apple", "Thiết bị Apple"),
    "00:1F:F3": ("Apple", "Thiết bị Apple"),
    "00:21:E9": ("Apple", "Thiết bị Apple"),
    "00:22:41": ("Apple", "Thiết bị Apple"),
    "00:23:12": ("Apple", "Thiết bị Apple"),
    "00:23:32": ("Apple", "Thiết bị Apple"),
    "00:23:6C": ("Apple", "Thiết bị Apple"),
    "00:23:DF": ("Apple", "Thiết bị Apple"),
    "00:24:36": ("Apple", "Thiết bị Apple"),
    "00:25:00": ("Apple", "Thiết bị Apple"),
    "00:25:4B": ("Apple", "Thiết bị Apple"),
    "00:25:BC": ("Apple", "Thiết bị Apple"),
    "00:26:08": ("Apple", "Thiết bị Apple"),
    "00:26:4A": ("Apple", "Thiết bị Apple"),
    "00:26:B0": ("Apple", "Thiết bị Apple"),
    "00:26:BB": ("Apple", "Thiết bị Apple"),
    "34:08:BC": ("Apple", "iPhone / iPad / Mac"),
    "34:12:98": ("Apple", "iPhone / iPad / Mac"),
    "34:15:9E": ("Apple", "iPhone / iPad / Mac"),
    "34:36:3B": ("Apple", "iPhone / iPad / Mac"),
    "34:ab:37": ("Apple", "iPhone / iPad / Mac"),
    "38:ca:da": ("Apple", "iPhone / iPad / Mac"),
    "3c:07:54": ("Apple", "iPhone / iPad / Mac"),
    "3c:15:c2": ("Apple", "iPhone / iPad / Mac"),
    "3c:ab:8e": ("Apple", "iPhone / iPad / Mac"),
    "40:6c:8f": ("Apple", "iPhone / iPad / Mac"),
    "40:98:ad": ("Apple", "iPhone / iPad / Mac"),
    "40:a6:d9": ("Apple", "iPhone / iPad / Mac"),
    "44:00:10": ("Apple", "iPhone / iPad / Mac"),
    "44:2a:60": ("Apple", "iPhone / iPad / Mac"),
    "48:43:7c": ("Apple", "iPhone / iPad / Mac"),
    "4c:32:75": ("Apple", "iPhone / iPad / Mac"),
    "50:ed:3c": ("Apple", "iPhone / iPad / Mac"),
    "58:55:ca": ("Apple", "iPhone / iPad / Mac"),
    "60:f4:45": ("Apple", "iPhone / iPad / Mac"),
    "64:a5:c3": ("Apple", "iPhone / iPad / Mac"),
    "70:3e:ac": ("Apple", "iPhone / iPad / Mac"),
    "78:7b:8a": ("Apple", "iPhone / iPad / Mac"),
    "80:49:71": ("Apple", "iPhone / iPad / Mac"),
    "88:66:a5": ("Apple", "iPhone / iPad / Mac"),
    "90:72:40": ("Apple", "iPhone / iPad / Mac"),
    "9c:20:7b": ("Apple", "iPhone / iPad / Mac"),
    "a4:83:e7": ("Apple", "iPhone / iPad / Mac"),
    "ac:bc:32": ("Apple", "iPhone / iPad / Mac"),
    "b8:78:26": ("Apple", "iPhone / iPad / Mac"),
    "c8:69:cd": ("Apple", "iPhone / iPad / Mac"),
    "d0:23:db": ("Apple", "iPhone / iPad / Mac"),
    "d8:a2:5e": ("Apple", "iPhone / iPad / Mac"),
    "e4:ce:8f": ("Apple", "iPhone / iPad / Mac"),
    "f0:18:98": ("Apple", "iPhone / iPad / Mac"),
    "f4:5c:89": ("Apple", "iPhone / iPad / Mac"),

    # Samsung
    "00:07:AB": ("Samsung", "Thiết bị Samsung"),
    "00:12:47": ("Samsung", "Thiết bị Samsung"),
    "00:15:99": ("Samsung", "Thiết bị Samsung"),
    "00:16:32": ("Samsung", "Thiết bị Samsung"),
    "00:17:C9": ("Samsung", "Thiết bị Samsung"),
    "00:18:AF": ("Samsung", "Thiết bị Samsung"),
    "00:1A:8A": ("Samsung", "Thiết bị Samsung"),
    "00:1C:43": ("Samsung", "Thiết bị Samsung"),
    "00:1D:25": ("Samsung", "Thiết bị Samsung"),
    "00:1E:E1": ("Samsung", "Thiết bị Samsung"),
    "00:21:19": ("Samsung", "Thiết bị Samsung"),
    "00:23:D7": ("Samsung", "Thiết bị Samsung"),
    "00:24:54": ("Samsung", "Thiết bị Samsung"),
    "00:24:90": ("Samsung", "Thiết bị Samsung"),
    "00:26:37": ("Samsung", "Thiết bị Samsung"),
    "00:26:5D": ("Samsung", "Thiết bị Samsung"),
    "08:08:C2": ("Samsung", "Galaxy / Smart TV"),
    "14:bb:6e": ("Samsung", "Galaxy / Smart TV"),
    "18:22:7e": ("Samsung", "Galaxy / Smart TV"),
    "24:4b:03": ("Samsung", "Galaxy / Smart TV"),
    "28:39:5e": ("Samsung", "Galaxy / Smart TV"),
    "28:77:77": ("Samsung", "Galaxy / Smart TV"),
    "30:07:4d": ("Samsung", "Galaxy / Smart TV"),
    "34:23:87": ("Samsung", "Galaxy / Smart TV"),
    "38:0b:40": ("Samsung", "Galaxy / Smart TV"),
    "3c:8b:fe": ("Samsung", "Galaxy / Smart TV"),
    "40:40:a7": ("Samsung", "Galaxy / Smart TV"),
    "44:4e:1a": ("Samsung", "Galaxy / Smart TV"),
    "48:44:f7": ("Samsung", "Galaxy / Smart TV"),
    "50:01:d9": ("Samsung", "Galaxy / Smart TV"),
    "50:56:bf": ("Samsung", "Galaxy / Smart TV"),
    "54:92:be": ("Samsung", "Galaxy / Smart TV"),
    "58:9e:35": ("Samsung", "Galaxy / Smart TV"),
    "5c:f6:dc": ("Samsung", "Galaxy / Smart TV"),
    "64:1c:ae": ("Samsung", "Galaxy / Smart TV"),
    "68:05:71": ("Samsung", "Galaxy / Smart TV"),
    "6c:2f:2c": ("Samsung", "Galaxy / Smart TV"),
    "70:2c:1f": ("Samsung", "Galaxy / Smart TV"),
    "78:1f:db": ("Samsung", "Galaxy / Smart TV"),
    "84:25:db": ("Samsung", "Galaxy / Smart TV"),
    "8c:77:12": ("Samsung", "Galaxy / Smart TV"),
    "94:65:2d": ("Samsung", "Galaxy / Smart TV"),
    "9c:02:98": ("Samsung", "Galaxy / Smart TV"),
    "a8:06:00": ("Samsung", "Galaxy / Smart TV"),
    "ac:5f:3e": ("Samsung", "Galaxy / Smart TV"),
    "b4:07:f9": ("Samsung", "Galaxy / Smart TV"),
    "bc:72:b9": ("Samsung", "Galaxy / Smart TV"),
    "c8:19:f7": ("Samsung", "Galaxy / Smart TV"),
    "cc:07:ab": ("Samsung", "Galaxy / Smart TV"),
    "d0:59:e4": ("Samsung", "Galaxy / Smart TV"),
    "dc:71:44": ("Samsung", "Galaxy / Smart TV"),
    "e4:58:b8": ("Samsung", "Galaxy / Smart TV"),
    "ec:11:27": ("Samsung", "Galaxy / Smart TV"),
    "f4:7b:5e": ("Samsung", "Galaxy / Smart TV"),

    # TP-Link
    "00:27:19": ("TP-Link", "Router / Access Point / Cục phát Wi-Fi"),
    "04:a1:51": ("TP-Link", "Router / Repeater / Camera Tapo"),
    "08:cc:81": ("TP-Link", "Router / Bộ mở rộng sóng / Cục phát Wi-Fi"),
    "14:cf:92": ("TP-Link", "Router Wi-Fi TP-Link"),
    "18:d6:c7": ("TP-Link", "Router Wi-Fi TP-Link"),
    "20:dc:e6": ("TP-Link", "Router Wi-Fi TP-Link"),
    "30:b5:c2": ("TP-Link", "Router Wi-Fi TP-Link"),
    "34:e8:94": ("TP-Link", "Router Wi-Fi TP-Link"),
    "50:c7:bf": ("TP-Link", "Tapo Smart Plug / Bulb / Camera"),
    "54:af:97": ("TP-Link", "Router Wi-Fi TP-Link"),
    "60:32:b1": ("TP-Link", "Router Wi-Fi TP-Link"),
    "64:66:b3": ("TP-Link", "Router Wi-Fi TP-Link"),
    "68:ff:7b": ("TP-Link", "Router Wi-Fi TP-Link"),
    "70:4f:57": ("TP-Link", "Router Wi-Fi TP-Link"),
    "74:da:88": ("TP-Link", "Router Wi-Fi TP-Link"),
    "84:16:f9": ("TP-Link", "Router Wi-Fi TP-Link"),
    "84:94:59": ("TP-Link", "Router Wi-Fi / Switch / AP"),
    "98:48:27": ("TP-Link", "Router Wi-Fi TP-Link"),
    "9c:a2:f4": ("TP-Link", "Router Wi-Fi TP-Link"),
    "a8:5e:45": ("TP-Link", "Router Wi-Fi TP-Link"),
    "b0:4e:26": ("TP-Link", "Router Wi-Fi TP-Link"),
    "b0:95:75": ("TP-Link", "Router Wi-Fi TP-Link"),
    "c0:25:e9": ("TP-Link", "Router Wi-Fi TP-Link"),
    "c4:6e:1f": ("TP-Link", "Router Wi-Fi TP-Link"),
    "c4:71:54": ("TP-Link", "Router Wi-Fi TP-Link"),
    "cc:32:e5": ("TP-Link", "Router Wi-Fi TP-Link"),
    "cc:72:2c": ("TP-Link", "Router Wi-Fi TP-Link"),
    "d4:6e:0e": ("TP-Link", "Router Wi-Fi TP-Link"),
    "d8:07:b6": ("TP-Link", "Router Wi-Fi TP-Link"),
    "d8:0d:17": ("TP-Link", "Router Wi-Fi TP-Link"),
    "d8:47:32": ("TP-Link", "Router Wi-Fi TP-Link"),
    "e4:c3:2a": ("TP-Link", "Router Wi-Fi TP-Link"),
    "e8:48:b8": ("TP-Link", "Router Wi-Fi TP-Link"),
    "ec:08:6b": ("TP-Link", "Router Wi-Fi TP-Link"),
    "ec:17:2f": ("TP-Link", "Router Wi-Fi TP-Link"),
    "f4:ec:38": ("TP-Link", "Router Wi-Fi TP-Link"),
    "f4:f2:6d": ("TP-Link", "Router Wi-Fi TP-Link"),

    # ZTE / Huawei / Viettel / VNPT / FPT Modems
    "d4:31:27": ("ZTE Corporation", "Modem cáp quang Viettel / VNPT (ZTE)"),
    "94:b4:0f": ("ZTE Corporation", "Thiết bị / Modem mạng ZTE"),
    "a8:bd:27": ("ZTE Corporation", "Thiết bị / Modem mạng ZTE"),
    "00:1e:10": ("Huawei", "Modem / Router Huawei"),
    "00:25:9e": ("Huawei", "Modem / Router Huawei"),
    "08:19:a6": ("Huawei", "Điện thoại / Modem Huawei"),
    "10:47:80": ("Huawei", "Modem / Router Huawei"),
    "20:08:89": ("Huawei", "Modem cáp quang Viettel (Huawei HG8045/8145)"),
    "24:69:68": ("Huawei", "Modem / Router Huawei"),
    "40:4d:8e": ("Huawei", "Modem / Router Huawei"),
    "48:46:fb": ("Huawei", "Modem / Router Huawei"),
    "48:db:50": ("Huawei", "Modem / Router Huawei"),
    "70:7b:e8": ("Huawei", "Modem / Router Huawei"),
    "ac:e2:15": ("Huawei", "Modem / Router Huawei"),
    "f4:63:1f": ("Huawei", "Modem / Router Huawei"),
    "f8:e7:1e": ("Huawei", "Modem / Router Huawei"),

    # Xiaomi
    "00:9e:c8": ("Xiaomi", "Điện thoại / Thiết bị thông minh Xiaomi"),
    "04:cf:8c": ("Xiaomi", "Điện thoại Xiaomi / Redmi / POCO"),
    "0c:98:38": ("Xiaomi", "Smart TV / Mi Box"),
    "14:f6:5a": ("Xiaomi", "Điện thoại / Thiết bị thông minh"),
    "18:59:36": ("Xiaomi", "Điện thoại Xiaomi"),
    "20:82:c0": ("Xiaomi", "Router Wi-Fi / Cục kích sóng Xiaomi"),
    "28:6c:07": ("Xiaomi", "Điện thoại Xiaomi"),
    "34:80:0d": ("Xiaomi", "Robot hút bụi / Camera Mi"),
    "34:ce:00": ("Xiaomi", "Điện thoại Xiaomi"),
    "3c:bd:3e": ("Xiaomi", "Điện thoại Xiaomi"),
    "44:23:7c": ("Xiaomi", "Điện thoại Xiaomi"),
    "50:64:2b": ("Xiaomi", "Thiết bị thông minh Xiaomi"),
    "58:44:98": ("Xiaomi", "Điện thoại Xiaomi"),
    "64:09:80": ("Xiaomi", "Điện thoại / TV Xiaomi"),
    "64:cc:2e": ("Xiaomi", "Điện thoại Xiaomi"),
    "78:11:dc": ("Xiaomi", "Router / Thiết bị Xiaomi"),
    "7c:49:eb": ("Xiaomi", "Điện thoại Xiaomi"),
    "88:c3:97": ("Xiaomi", "Điện thoại Xiaomi"),
    "98:fa:e3": ("Xiaomi", "Điện thoại Xiaomi"),
    "a4:77:33": ("Xiaomi", "Điện thoại Xiaomi"),
    "ac:c1:ee": ("Xiaomi", "Điện thoại Xiaomi"),
    "b0:e5:ed": ("Xiaomi", "Điện thoại Xiaomi"),
    "d4:97:0b": ("Xiaomi", "Điện thoại Xiaomi"),
    "e4:aa:ea": ("Xiaomi", "Điện thoại Xiaomi"),
    "f8:a4:50": ("Xiaomi", "Điện thoại Xiaomi"),

    # Espressif (ESP8266 / ESP32 - Chip IoT dùng trong công tắc thông minh, đèn, Tuya, Sonoff)
    "18:fe:34": ("Espressif IoT", "Thiết bị nhà thông minh (ESP8266/ESP32)"),
    "24:0a:c4": ("Espressif IoT", "Công tắc / Cảm biến thông minh"),
    "24:62:ab": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "24:6f:28": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "24:b2:de": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "2c:3a:e8": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "2c:f4:32": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "30:ae:a4": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "3c:61:05": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "3c:71:bf": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "40:22:d8": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "48:3f:da": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "48:55:19": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "54:5a:a6": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "60:01:94": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "68:c6:3a": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "80:7d:3a": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "84:0d:8e": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "84:cc:a8": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "84:f3:eb": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "94:b9:7e": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "a4:cf:12": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "a8:03:2a": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "ac:67:b2": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "b4:e6:2d": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "bc:dd:c2": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "c4:4f:33": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "cc:50:e3": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "d8:a0:1d": ("Espressif IoT", "Thiết bị nhà thông minh"),
    "ec:fa:bc": ("Espressif IoT", "Thiết bị nhà thông minh"),

    # Intel
    "00:02:B3": ("Intel", "Card mạng máy tính Intel"),
    "00:03:47": ("Intel", "Card mạng máy tính Intel"),
    "00:0E:0C": ("Intel", "Card mạng máy tính Intel"),
    "00:13:02": ("Intel", "Card mạng máy tính Intel"),
    "00:15:00": ("Intel", "Card mạng máy tính Intel"),
    "00:16:76": ("Intel", "Card mạng máy tính Intel"),
    "00:18:DE": ("Intel", "Card mạng máy tính Intel"),
    "00:19:D1": ("Intel", "Card mạng máy tính Intel"),
    "00:1B:77": ("Intel", "Card mạng máy tính Intel"),
    "00:1C:BF": ("Intel", "Card mạng máy tính Intel"),
    "00:1D:E0": ("Intel", "Card mạng máy tính Intel"),
    "00:1E:64": ("Intel", "Card mạng máy tính Intel"),
    "00:21:6A": ("Intel", "Card mạng máy tính Intel"),
    "00:22:FB": ("Intel", "Card mạng máy tính Intel"),
    "00:24:D7": ("Intel", "Card mạng máy tính Intel"),
    "00:26:C7": ("Intel", "Card mạng máy tính Intel"),
    "00:27:0E": ("Intel", "Card mạng máy tính Intel"),
    "08:11:96": ("Intel", "Card mạng Wi-Fi Laptop Intel"),
    "24:41:8c": ("Intel", "Card mạng Wi-Fi Laptop Intel"),
    "34:13:e8": ("Intel", "Card mạng Wi-Fi Laptop Intel"),
    "3c:6a:9d": ("Intel", "Card mạng Wi-Fi Laptop Intel"),
    "48:f1:7f": ("Intel", "Card mạng Wi-Fi Laptop Intel"),
    "58:91:cf": ("Intel", "Card mạng Wi-Fi Laptop Intel"),
    "60:57:18": ("Intel", "Card mạng Wi-Fi Laptop Intel"),
    "68:05:ca": ("Intel", "Card mạng Wi-Fi Laptop Intel"),
    "70:1c:e8": ("Intel", "Card mạng Wi-Fi Laptop Intel"),
    "7c:21:4a": ("Intel", "Card mạng Wi-Fi Laptop Intel"),
    "80:38:fb": ("Intel", "Card mạng Wi-Fi Laptop Intel"),
    "8c:8d:28": ("Intel", "Card mạng Wi-Fi Laptop Intel"),
    "9c:29:76": ("Intel", "Card mạng Wi-Fi Laptop Intel"),
    "a4:4c:c8": ("Intel", "Card mạng Wi-Fi Laptop Intel"),
    "b0:3c:dc": ("Intel", "Card Wi-Fi 6E/7 Intel Corporation"),
    "b8:8a:ec": ("Intel", "Card mạng Wi-Fi Laptop Intel"),
    "c8:9c:dc": ("Intel", "Card mạng Wi-Fi Laptop Intel"),
    "d0:7e:35": ("Intel", "Card mạng Wi-Fi Laptop Intel"),
    "dc:41:a9": ("Intel", "Card mạng Wi-Fi Laptop Intel"),
    "e4:70:b8": ("Intel", "Card mạng Wi-Fi Laptop Intel"),
    "f0:d5:bf": ("Intel", "Card mạng Wi-Fi Laptop Intel"),
    "f8:89:d2": ("Intel", "Card mạng Wi-Fi Laptop Intel"),

    # Asus
    "00:0C:6E": ("ASUS", "Laptop / Mainboard / Router ASUS"),
    "00:15:F2": ("ASUS", "Laptop / Router ASUS"),
    "00:1A:92": ("ASUS", "Laptop / Router ASUS"),
    "00:1E:8C": ("ASUS", "Laptop / Router ASUS"),
    "00:22:15": ("ASUS", "Laptop / Router ASUS"),
    "00:23:54": ("ASUS", "Laptop / Router ASUS"),
    "00:24:8C": ("ASUS", "Laptop / Router ASUS"),
    "04:d9:f5": ("ASUS", "Laptop / Router ASUS"),
    "10:7b:44": ("ASUS", "Laptop / Router ASUS"),
    "18:31:bf": ("ASUS", "Laptop / Router ASUS"),
    "2c:fd:a1": ("ASUS", "Laptop / Router ASUS"),
    "30:85:a9": ("ASUS", "Laptop / Router ASUS"),
    "40:16:7e": ("ASUS", "Laptop / Router ASUS"),
    "50:46:5d": ("ASUS", "Laptop / Router ASUS"),
    "54:04:a6": ("ASUS", "Laptop / Router ASUS"),
    "60:45:cb": ("ASUS", "Laptop / Router ASUS"),
    "70:4d:7b": ("ASUS", "Laptop / Router ASUS"),
    "ac:22:0b": ("ASUS", "Laptop / Router ASUS"),
    "bc:ee:7b": ("ASUS", "Laptop / Router ASUS"),
    "d8:50:e6": ("ASUS", "Laptop / Router ASUS"),
    "f0:79:59": ("ASUS", "Laptop / Router ASUS"),

    # Dell
    "00:14:22": ("Dell", "Máy tính / Laptop Dell"),
    "18:66:da": ("Dell", "Máy tính / Laptop Dell"),
    "24:b6:fd": ("Dell", "Máy tính / Laptop Dell"),
    "54:bf:64": ("Dell", "Máy tính / Laptop Dell"),
    "74:e6:e2": ("Dell", "Máy tính / Laptop Dell"),
    "8c:04:ba": ("Dell", "Máy tính / Laptop Dell"),
    "a4:1f:72": ("Dell", "Máy tính / Laptop Dell"),
    "b8:ac:6f": ("Dell", "Máy tính / Laptop Dell"),
    "d4:81:d7": ("Dell", "Máy tính / Laptop Dell"),
    "ec:f4:bb": ("Dell", "Máy tính / Laptop Dell"),

    # HP
    "00:17:A4": ("HP", "Máy tính / Máy in HP"),
    "00:25:B3": ("HP", "Máy tính / Máy in HP"),
    "10:1f:74": ("HP", "Máy tính / Máy in HP"),
    "28:92:4a": ("HP", "Máy tính / Máy in HP"),
    "3c:52:82": ("HP", "Máy tính / Máy in HP"),
    "64:51:06": ("HP", "Máy tính / Máy in HP"),
    "70:5a:0f": ("HP", "Máy tính / Máy in HP"),
    "84:34:97": ("HP", "Máy tính / Máy in HP"),
    "9c:b6:54": ("HP", "Máy tính / Máy in HP"),
    "c8:d9:d2": ("HP", "Máy tính / Máy in HP"),

    # Google
    "00:1A:11": ("Google", "Google Nest / Chromecast / Pixel"),
    "3c:5a:37": ("Google", "Google Nest / Chromecast / Pixel"),
    "48:d6:d5": ("Google", "Google Nest / Chromecast / Pixel"),
    "54:60:09": ("Google", "Google Nest / Chromecast / Pixel"),
    "70:3a:cb": ("Google", "Google Nest / Chromecast / Pixel"),
    "94:eb:2c": ("Google", "Google Nest / Chromecast / Pixel"),
    "a4:77:60": ("Google", "Google Nest / Chromecast / Pixel"),
    "d8:6c:63": ("Google", "Google Nest / Chromecast / Pixel"),
    "e8:9f:80": ("Google", "Google Nest / Chromecast / Pixel"),
    "f4:03:04": ("Google", "Google Nest / Chromecast / Pixel"),
    "f8:8f:ca": ("Google", "Google Nest / Chromecast / Pixel"),

    # Sony
    "00:01:4A": ("Sony", "Smart TV / PlayStation / Âm thanh"),
    "00:13:15": ("Sony", "Smart TV / PlayStation"),
    "00:19:C5": ("Sony", "Smart TV / PlayStation"),
    "00:1D:BA": ("Sony", "Smart TV / PlayStation"),
    "00:24:8D": ("Sony", "Smart TV / PlayStation"),
    "28:0d:fc": ("Sony", "Smart TV / PlayStation"),
    "70:9e:29": ("Sony", "Smart TV / PlayStation"),
    "ac:9b:0a": ("Sony", "Smart TV / PlayStation"),
    "fc:f1:36": ("Sony", "Smart TV / PlayStation"),

    # LG
    "00:1C:62": ("LG Electronics", "Smart TV / Thiết bị gia dụng LG"),
    "00:1F:6B": ("LG Electronics", "Smart TV / Thiết bị LG"),
    "10:68:38": ("LG Electronics", "Smart TV / Thiết bị LG"),
    "20:3d:b2": ("LG Electronics", "Smart TV / Thiết bị LG"),
    "48:59:29": ("LG Electronics", "Smart TV / Thiết bị LG"),
    "78:5d:c8": ("LG Electronics", "Smart TV / Thiết bị LG"),
    "a8:23:fe": ("LG Electronics", "Smart TV / Thiết bị LG"),
    "b8:bc:5b": ("LG Electronics", "Smart TV / Thiết bị LG"),
    "cc:2d:83": ("LG Electronics", "Smart TV / Thiết bị LG"),

    # Hikvision / Dahua / Imou (Camera an ninh)
    "00:12:12": ("Hikvision", "Camera an ninh Hikvision / Ezviz"),
    "44:19:b6": ("Hikvision", "Camera an ninh Hikvision / Ezviz"),
    "bc:54:51": ("Hikvision", "Camera an ninh Hikvision / Ezviz"),
    "c4:2f:90": ("Hikvision", "Camera an ninh Hikvision / Ezviz"),
    "d0:76:8f": ("Hikvision", "Camera an ninh Hikvision / Ezviz"),
    "14:a7:8b": ("Dahua", "Camera an ninh Dahua / Imou"),
    "3c:ef:8c": ("Dahua", "Camera an ninh Dahua / Imou"),
    "40:24:b2": ("Dahua", "Camera an ninh Dahua / Imou"),
    "90:02:a9": ("Dahua", "Camera an ninh Dahua / Imou"),
    "a0:bd:cd": ("Dahua", "Camera an ninh Dahua / Imou"),

    # Tenda / Totolink / Mercusys
    "00:b0:0c": ("Tenda", "Router / Cục phát Wi-Fi Tenda"),
    "50:2b:73": ("Tenda", "Router / Cục phát Wi-Fi Tenda"),
    "c8:3a:35": ("Tenda", "Router / Cục phát Wi-Fi Tenda"),
    "00:1f:a4": ("TOTOLINK", "Router / Cục kích Wi-Fi Totolink"),
    "70:af:6a": ("TOTOLINK", "Router / Cục kích Wi-Fi Totolink"),
    "a0:40:a0": ("TOTOLINK", "Router / Cục kích Wi-Fi Totolink"),
    "74:05:a5": ("Mercusys", "Router / Repeater Wi-Fi Mercusys"),
    "94:08:53": ("Mercusys", "Router / Repeater Wi-Fi Mercusys"),

    # Realtek / MediaTek / VM
    "00:0e:2e": ("Realtek", "Card mạng Realtek"),
    "00:e0:4c": ("Realtek", "Card mạng Realtek"),
    "52:54:00": ("QEMU / KVM", "Máy ảo Virtual Machine"),
    "00:50:56": ("VMware", "Máy ảo VMware"),
    "08:00:27": ("VirtualBox", "Máy ảo VirtualBox"),
}

# Chuẩn hoá OUI database dạng chữ hoa
_NORMALIZED_DB = {k.upper(): v for k, v in OUI_DATABASE.items()}


def is_randomized_mac(mac_str: str) -> bool:
    """
    Kiểm tra xem địa chỉ MAC có phải là MAC ngẫu nhiên / cục bộ (Locally Administered) hay không.
    Theo chuẩn IEEE 802, bit 1 của byte đầu tiên = 1 nghĩa là địa chỉ cục bộ (Private/Randomized MAC).
    Các ký tự thứ 2 của MAC thường là: 2, 6, A, E (ví dụ: x2:xx, x6:xx, xA:xx, xE:xx).
    Tính năng này mặc định trên:
      - iPhone/iPad (iOS 14+): "Private Wi-Fi Address"
      - Android 10+: "MAC Address Randomization"
      - Windows 10/11: "Random hardware addresses"
    """
    if not mac_str or len(mac_str) < 2:
        return False
    try:
        first_byte_str = mac_str[:2]
        first_byte = int(first_byte_str, 16)
        # Bit 1 (bit thứ 2 từ phải sang: 0x02) = 1 -> Locally administered
        return (first_byte & 0x02) != 0
    except ValueError:
        return False


def lookup_vendor(mac_str: str) -> tuple[str, str, str]:
    """
    Tra cứu nhà sản xuất từ địa chỉ MAC.
    Trả về: (VendorName, DeviceHint, Category)
      - Category: 'router', 'mobile', 'pc', 'iot', 'camera', 'private', 'system', 'unknown'
    """
    if not mac_str or mac_str.upper() in ("FF:FF:FF:FF:FF:FF", "FF-FF-FF-FF-FF-FF"):
        return "Broadcast / Hệ thống", "Địa chỉ phát thanh mạng LAN", "system"

    clean_mac = mac_str.strip().upper().replace("-", ":")
    parts = clean_mac.split(":")

    if len(parts) >= 3:
        oui = ":".join(parts[:3])
        if oui in _NORMALIZED_DB:
            vendor, hint = _NORMALIZED_DB[oui]
            # Phân loại danh mục
            category = "unknown"
            v_lower = vendor.lower()
            h_lower = hint.lower()
            if "router" in h_lower or "modem" in h_lower or "cục phát" in h_lower or "ap" in h_lower:
                category = "router"
            elif "camera" in h_lower:
                category = "camera"
            elif "iot" in v_lower or "thông minh" in h_lower or "esp" in h_lower:
                category = "iot"
            elif "apple" in v_lower or "samsung" in v_lower or "xiaomi" in v_lower:
                category = "mobile"
            elif "intel" in v_lower or "dell" in v_lower or "hp" in v_lower or "asus" in v_lower:
                category = "pc"
            return vendor, hint, category

    # Nếu không có trong database cố định, kiểm tra xem có phải Randomized MAC không
    if is_randomized_mac(clean_mac):
        return (
            "Thiết bị bảo mật (MAC riêng tư)",
            "Thường là iPhone (iOS 14+), Android (10+), hoặc Windows 11 bật Private Wi-Fi",
            "private",
        )

    return "Chưa rõ hãng", "Thiết bị mạng nội bộ", "unknown"
