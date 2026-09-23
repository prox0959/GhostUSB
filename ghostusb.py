# GhostUSB - Windows USB Adli Bilisim (Forensics) Analiz Araci
# TR: Bu script, Windows Kayit Defteri'ni (Registry) inceleyerek bilgisayara
# baglanmis USB bellekler ve donanimlarin adli zaman cizelgesini cikarir.

import sys
import winreg
import datetime
import json
import os

# Windows konsolunda Turkce ve Unicode karakterlerin hatasiz basilmasi icin UTF-8 ayarlamasi
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

def parse_usb_registry():
    r"""
    Windows Kayit Defteri'ndeki hem USBSTOR (Harici Disk/Bellek) hem de USB anahtarlarini tarayarak
    tespit edilen donanimlari, uretici (VID) / model (PID) ve zaman damgalarini toplar.
    
    TR: HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR ve HKLM\SYSTEM\CurrentControlSet\Enum\USB tarar.
    """
    devices = []
    
    # Taranacak anahtarlar: 
    # 1. USBSTOR: Flash bellekler, harici diskler
    # 2. USB: Genel USB kontrolculeri, baglanan tum cevre birimleri
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
                # ROOT_HUB gibi sanal portlari filtreleyelim
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
                        
                        # Cihaz tanimi (DeviceDesc veya FriendlyName)
                        friendly_name = None
                        for val_name in ["FriendlyName", "DeviceDesc"]:
                            try:
                                val, _ = winreg.QueryValueEx(inst_key, val_name)
                                if val:
                                    # '@oem.inf,...' gibi Windows tanimlarini temizle
                                    if ";" in val:
                                        friendly_name = val.split(";")[-1]
                                    else:
                                        friendly_name = val
                                    break
                            except FileNotFoundError:
                                pass
                        
                        if not friendly_name:
                            friendly_name = device_name
                        
                        # Son degistirilme zamani (LastWriteTime)
                        _, _, last_modified_filetime = winreg.QueryInfoKey(inst_key)
                        
                        try:
                            # 116444736000000000 = 1 Ocak 1601 - 1 Ocak 1970 arasi fark
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

    # En yeniden en eskiye dogru sirala
    devices.sort(key=lambda x: x["last_seen"], reverse=True)
    return devices

def print_forensic_report(devices):
    """
    Tespit edilen USB cihazlarini adli bilisim formatinda ekrana basar ve JSON kaydeder.
    """
    print("\n" + "="*85)
    print(" [GHOSTUSB] - WINDOWS USB ADLI BILISIM VE DONANIM ZAMAN CIZELGESI")
    print("="*85)
    
    if not devices:
        print("[-] Sistemde kayitli USB aygit izi bulunamadi.")
        return
        
    print(f"[*] Toplam {len(devices)} adet USB donanim kaydi tespit edildi:\n")
    print(f"{'#':<3} | {'Cihaz / Model':<35} | {'Kategori':<17} | {'Son Baglanti':<19}")
    print("-" * 85)
    
    for idx, dev in enumerate(devices, 1):
        name = (dev['name'][:32] + '...') if len(dev['name']) > 35 else dev['name']
        print(f"{idx:<3} | {name:<35} | {dev['type']:<17} | {dev['last_seen']:<19}")
        
    print("="*85)
    
    out_file = "usb_forensics_report.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(devices, f, indent=4, ensure_ascii=False)
    print(f"\n[+] Adli analiz raporu JSON olarak kaydedildi: {out_file}\n")

if __name__ == "__main__":
    found_devices = parse_usb_registry()
    print_forensic_report(found_devices)
