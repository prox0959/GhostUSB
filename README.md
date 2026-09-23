# 🕵️‍♂️ GhostUSB

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**A lightweight Windows USB artifact forensics and timeline extraction tool.**

</div>

---

## 🔍 What is GhostUSB?
When an external USB drive (flash drive, external HDD) is plugged into a Windows computer, the operating system permanently logs its hardware identifier, serial number, and timestamp in the Windows Registry under `USBSTOR`. Even after the USB drive is unplugged, the digital forensic footprint remains.

**GhostUSB** queries the Windows Registry (`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`) to rebuild an ad-hoc forensic timeline of every USB mass storage device ever mounted to the system.

## ✨ Features
- ⚡ **Zero External Dependencies:** Built entirely with Python standard library (`winreg`, `datetime`, `json`).
- 🕒 **Timestamp Decoding:** Translates Windows 64-bit `FILETIME` structures into human-readable ISO timestamps.
- 📋 **Automated Forensic Reporting:** Outputs both a clean console table and an exportable JSON artifact (`usb_forensics_report.json`).

## 🚀 Usage

```bash
# Clone the repository
git clone https://github.com/prox0959/GhostUSB.git
cd GhostUSB

# Run directly (No pip install needed!)
python ghostusb.py
```

## ⚖️ License
MIT License. Built for digital forensics and incident response (DFIR) education.
