# GhostUSB - Windows USB Forensics & Artifact Timeline Tool
# TR: Windows Kayit Defteri'ndeki USBSTOR ve USB donanim izlerini adli bilisim formatinda cozumler.

import sys
import winreg
import datetime
import json
import os
import argparse

# UTF-8 console output setup for Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Multilingual UI Dictionary (EN / TR)
STRINGS = {
    "en": {
        "title": " [GHOSTUSB] - WINDOWS USB FORENSICS & HARDWARE ARTIFACT TIMELINE",
        "no_devices": "[-] No USB device artifacts found in the system registry.",
        "found_prefix": "[*] Discovered a total of",
        "found_suffix": "USB hardware connection records:\n",
        "col_num": "#",
        "col_name": "Device / Model Name",
        "col_type": "Category",
        "col_date": "Last Connected (Local)",
        "saved_report": "[+] Forensic report successfully saved to JSON:",
        "unknown_time": "Unknown"
    },
    "tr": {
        "title": " [GHOSTUSB] - WINDOWS USB ADLI BILISIM VE DONANIM ZAMAN CIZELGESI",
        "no_devices": "[-] Sistem kayit defterinde USB aygit izi bulunamadi.",
        "found_prefix": "[*] Toplam",
        "found_suffix": "adet USB donanim kaydi tespit edildi:\n",
        "col_num": "#",
        "col_name": "Cihaz / Model Adi",
        "col_type": "Kategori",
        "col_date": "Son Baglanti (Yerel)",
        "saved_report": "[+] Adli analiz raporu basariyla kaydedildi:",
        "unknown_time": "Bilinmiyor"
    }
}

def parse_usb_registry():
    r"""
    Scans Windows Registry for USBSTOR (Mass storage) and USB (Controllers/Peripherals).
    TR: HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR ve HKLM\SYSTEM\CurrentControlSet\Enum\USB tarar.
    """
    devices = []
    target_paths = [
        (r"SYSTEM\CurrentControlSet\Enum\USBSTOR", "USB Mass Storage"),
        (r"SYSTEM\CurrentControlSet\Enum\USB", "USB Device")
    ]
    
    for reg_path, category in target_paths:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_READ)
        except Exception:
            continue

        try:
            num_subkeys, _, _ = winreg.QueryInfoKey(key)
        except Exception:
            winreg.CloseKey(key)
            continue

        for i in range(num_subkeys):
            try:
                device_name = winreg.EnumKey(key, i)
                if "ROOT_HUB" in device_name:
                    continue
                    
                device_key_path = f"{reg_path}\\{device_name}"
                device_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, device_key_path, 0, winreg.KEY_READ)
                
                serial_count, _, _ = winreg.QueryInfoKey(device_key)
                
                for j in range(serial_count):
                    try:
                        instance_id = winreg.EnumKey(device_key, j)
                        inst_key_path = f"{device_key_path}\\{instance_id}"
                        inst_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, inst_key_path, 0, winreg.KEY_READ)
                        
                        friendly_name = None
                        for val_name in ["FriendlyName", "DeviceDesc"]:
                            try:
                                val, _ = winreg.QueryValueEx(inst_key, val_name)
                                if val:
                                    if ";" in val:
                                        friendly_name = val.split(";")[-1]
                                    else:
                                        friendly_name = val
                                    break
                            except FileNotFoundError:
                                pass
                        
                        if not friendly_name:
                            friendly_name = device_name
                        
                        _, _, last_modified_filetime = winreg.QueryInfoKey(inst_key)
                        
                        try:
                            timestamp = (last_modified_filetime - 116444736000000000) / 10000000
                            date_str = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                        except Exception:
                            date_str = "Bilinmiyor"
                        
                        devices.append({
                            "type": category,
                            "name": friendly_name,
                            "hardware_id": device_name,
                            "instance_id": instance_id,
                            "last_seen": date_str
                        })
                        
                        winreg.CloseKey(inst_key)
                    except Exception:
                        continue
                        
                winreg.CloseKey(device_key)
            except Exception:
                continue

        winreg.CloseKey(key)

    devices.sort(key=lambda x: x["last_seen"], reverse=True)
    return devices

def print_forensic_report(devices, lang="en"):
    """
    Prints the tabular forensic report and writes JSON artifact.
    """
    t = STRINGS[lang]
    print("\n" + "="*85)
    print(t["title"])
    print("="*85)
    
    if not devices:
        print(t["no_devices"])
        return
        
    print(f"{t['found_prefix']} {len(devices)} {t['found_suffix']}")
    print(f"{t['col_num']:<3} | {t['col_name']:<35} | {t['col_type']:<17} | {t['col_date']:<19}")
    print("-" * 85)
    
    for idx, dev in enumerate(devices, 1):
        name = (dev['name'][:32] + '...') if len(dev['name']) > 35 else dev['name']
        print(f"{idx:<3} | {name:<35} | {dev['type']:<17} | {dev['last_seen']:<19}")
        
    print("="*85)
    
    out_file = "usb_forensics_report.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(devices, f, indent=4, ensure_ascii=False)
    print(f"\n{t['saved_report']} {out_file}\n")

def main():
    parser = argparse.ArgumentParser(description="GhostUSB - Windows USB Forensics Artifact Extractor")
    parser.add_argument("-l", "--lang", choices=["en", "tr"], default="en", help="Language for output (en: English, tr: Turkish)")
    args = parser.parse_args()
    
    found_devices = parse_usb_registry()
    print_forensic_report(found_devices, lang=args.lang)

if __name__ == "__main__":
    main()
