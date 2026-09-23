# GhostUSB - Windows USB Adli Bilişim (Forensics) Analiz Aracı
# TR: Bu script, Windows Kayıt Defteri'ni (Registry) inceleyerek bilgisayara
# daha önce takılmış tüm USB belleklerin izini sürer ve zaman çizelgesi çıkarır.

import winreg
import datetime
import json
import os

def parse_usb_stor():
    """
    Windows Kayıt Defteri'ndeki USBSTOR anahtarını okuyarak geçmişte takılan
    USB belleklerin marka, model, seri numarası ve son bağlantı zamanını çıkarır.
    
    TR: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR yolundaki kayıtları tarar.
    """
    devices = []
    reg_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    
    try:
        # HKEY_LOCAL_MACHINE anahtarını salt-okunur (read-only) açıyoruz
        # TR: Sistem kayıt defterine zarar vermemek için sadece okuma yetkisiyle açılır.
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_READ)
    except FileNotFoundError:
        print("[!] USBSTOR anahtarı bulunamadı (Bu makinede hiç USB takılmamış olabilir).")
        return devices
    except PermissionError:
        print("[!] Yetki hatası: Registry okumak için gerekirse terminali Yönetici olarak çalıştırın.")
        return devices

    num_subkeys, _, _ = winreg.QueryInfoKey(key)

    for i in range(num_subkeys):
        try:
            device_name = winreg.EnumKey(key, i)
            device_key_path = f"{reg_path}\\{device_name}"
            device_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, device_key_path, 0, winreg.KEY_READ)
            
            serial_count, _, _ = winreg.QueryInfoKey(device_key)
            
            for j in range(serial_count):
                serial_num = winreg.EnumKey(device_key, j)
                serial_key_path = f"{device_key_path}\\{serial_num}"
                serial_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, serial_key_path, 0, winreg.KEY_READ)
                
                # Cihazın kullanıcı dostu adını (FriendlyName) almaya çalış
                try:
                    friendly_name, _ = winreg.QueryValueEx(serial_key, "FriendlyName")
                except FileNotFoundError:
                    friendly_name = device_name # Bulunamazsa donanım kimliğini kullan
                
                # Kayıt anahtarının son değiştirilme zamanını (LastWriteTime) al
                # TR: Bu zaman damgası genellikle cihazın ilk/son takılma anına tekabül eder.
                _, _, last_modified_filetime = winreg.QueryInfoKey(serial_key)
                
                # Windows FileTime (100-nanosaniyelik aralıklar) -> Unix Zamanına Çevirme
                try:
                    # 116444736000000000 = 1 Ocak 1601 ile 1 Ocak 1970 arasındaki mikro saniyeler
                    timestamp = (last_modified_filetime - 116444736000000000) / 10000000
                    date_str = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    date_str = "Bilinmiyor"
                
                devices.append({
                    "device_model": friendly_name,
                    "hardware_id": device_name,
                    "serial_number": serial_num,
                    "last_connected": date_str
                })
                
                winreg.CloseKey(serial_key)
            winreg.CloseKey(device_key)
        except Exception:
            continue

    winreg.CloseKey(key)
    return devices

def print_forensic_report(devices):
    """
    Tespit edilen USB cihazlarını şık bir ASCII tablo ve adli bilişim raporu olarak basar.
    """
    print("\n" + "="*80)
    print(" 🕵️‍♂️  GHOSTUSB - WINDOWS USB ADLİ BİLİŞİM RAPORU (FORENSICS TIMELINE)")
    print("="*80)
    
    if not devices:
        print("[-] Sistemde kayıtlı harici USB bellek izi tespit edilemedi.")
        return
        
    print(f"[*] Toplam {len(devices)} adet USB bellek izi bulundu:\n")
    print(f"{'#':<3} | {'Cihaz / Model':<28} | {'Seri Numarası':<20} | {'Zaman Damgası':<19}")
    print("-" * 80)
    
    for idx, dev in enumerate(devices, 1):
        name = (dev['device_model'][:25] + '...') if len(dev['device_model']) > 28 else dev['device_model']
        serial = (dev['serial_number'][:17] + '...') if len(dev['serial_number']) > 20 else dev['serial_number']
        print(f"{idx:<3} | {name:<28} | {serial:<20} | {dev['last_connected']:<19}")
        
    print("="*80)
    
    # Raporu JSON dosyasına kaydet
    out_file = "usb_forensics_report.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(devices, f, indent=4, ensure_ascii=False)
    print(f"\n[+] Detaylı adli analiz verisi kaydedildi: {out_file}")

if __name__ == "__main__":
    found_devices = parse_usb_stor()
    print_forensic_report(found_devices)
