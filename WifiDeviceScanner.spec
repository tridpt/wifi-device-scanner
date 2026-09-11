# -*- mode: python ; coding: utf-8 -*-
import os
import sys
from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules

block_cipher = None

# Thu thập đầy đủ dữ liệu, nhị phân và import ẩn của CustomTkinter & Pillow
datas = [
    ('assets', 'assets'),
]

# Thêm saved_wol_devices.json nếu có
if os.path.exists('saved_wol_devices.json'):
    datas.append(('saved_wol_devices.json', '.'))

ctk_datas, ctk_binaries, ctk_hiddenimports = collect_all('customtkinter')
datas += ctk_datas
binaries = ctk_binaries

hiddenimports = [
    'scanner',
    'oui_db',
    'mac_blocker',
    'port_scanner',
    'ping_monitor',
    'security_audit',
    'wake_on_lan',
    'spy_camera_detector',
    'camera_streamer',
    'camera_auth_checker',
    'network_topology',
    'lan_shared_folders',
    'lan_speedtest',
    'wifi_channel_analyzer',
    'export_utils',
    'mac_randomizer',
    'ctypes',
    'ctypes.wintypes',
    'winsound',
    'PIL',
    'PIL.Image',
    'PIL.ImageTk',
    'PIL.ImageDraw',
    'urllib.request',
    'json',
    'socket',
    'subprocess',
    'threading',
    'queue',
    'ipaddress',
    'webbrowser',
] + ctk_hiddenimports

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='WifiDeviceScanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/app_icon.ico',
)
