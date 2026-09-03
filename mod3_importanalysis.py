import pefile
import logging, json
logging.basicConfig(level = logging.ERROR)
SUSPICIOUS_IMPORTS = {
    "process_injection": [
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
        "NtUnmapViewOfSection", "SetThreadContext", "GetThreadContext",
        "QueueUserAPC", "NtWriteVirtualMemory", "NtCreateThreadEx"
    ],
    "anti_debug_anti_vm": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugStringA", "GetTickCount", "QueryPerformanceCounter",
        "FindWindowA"  # hay dùng để tìm cửa sổ debugger/sandbox
    ],
    "dynamic_resolution": [
        "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "LoadLibraryExA"
    ],
    "network_c2": [
        "InternetOpenA", "InternetOpenUrlA", "InternetReadFile",
        "URLDownloadToFileA", "send", "recv", "connect", "WSAStartup",
        "HttpSendRequestA", "InternetConnectA"
    ],
    "persistence": [
        "RegSetValueExA", "RegCreateKeyExA", "RegOpenKeyExA",
        "CreateServiceA", "StartServiceA"
    ],
    "crypto": [
        "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA",
        "CryptGenKey", "CryptCreateHash"
    ],
    "keylogging_spying": [
        "SetWindowsHookExA", "GetAsyncKeyState", "GetKeyState",
        "GetForegroundWindow"
    ],
    "process_execution": [
        "CreateProcessA", "WinExec", "ShellExecuteA", "CreateProcessW"
    ]
}

RISK_WEIGHTS = {
    "process_injection":  5,   # hiếm ở app sạch, hậu quả nặng nhất — chiếm quyền tiến trình khác
    "persistence":        4,   # hiếm ở app thường (trừ installer), muốn tồn tại lâu dài trong máy
    "keylogging_spying":  4,   # hiếm, mục đích gần như luôn là do thám
    "crypto":             3,   # app hợp lệ cũng dùng (trình duyệt, VPN) nhưng ransomware dùng để mã hóa file nạn nhân
    "dynamic_resolution": 3,   # LoadLibrary/GetProcAddress phổ biến vừa phải, nhưng hay đi kèm evasion
    "process_execution":  3,   # CreateProcess/WinExec — app cài đặt cũng dùng, nhưng cũng là cách spawn payload
    "network_c2":         2,   # rất phổ biến ở app sạch (browser, game...) — đặc trưng thấp
    "anti_debug_anti_vm": 2,   # tự nó không gây hại, chỉ hỗ trợ né phát hiện
}

COMBO_BONUS = {
    ("persistence", "network_c2"):
        "Backdoor/trojan điều khiển từ xa — cài xong ở lại vĩnh viễn + liên tục gọi về server hacker",

    ("crypto", "network_c2"):
        "Ransomware kiểu hit-and-run — mã hóa file nạn nhân rồi gửi key về server, không cần persistence",

    ("keylogging_spying", "network_c2"):
        "Spyware/stealer — thu thập thông tin bàn phím/màn hình rồi gửi ra ngoài",

    ("process_injection", "dynamic_resolution"):
        "Evasion + injection — tự tra API lúc runtime để né static analysis, đồng thời tiêm code vào tiến trình khác",
}
def import_analysis(filepath:str)->dict:
    try:
        imported_functions = {}
        pe = pefile.PE(filepath)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for dll in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = dll.dll.decode()
                imported_functions[dll_name] = []
                for function in dll.imports:
                    if function.name == None:
                        if function.ordinal == None:
                            imported_functions[dll_name].append(f'{function.address} is suspicious')
                        else :
                            imported_functions[dll_name].append(f'{function.ordinal}')
                    else :
                        imported_functions[dll_name].append(f'{function.name.decode()}')
    except pefile.PEFormatError:
        logging.error("Pe format error")
        return None
    return imported_functions
def check_if_in_blacklist(function_name: str):
    for key, value in SUSPICIOUS_IMPORTS.items():
        if function_name in value:
            return key
    return None
def filter_suspicious_imports(filepath: str)->dict:
    """ dll list returned from import_analysis func"""
    import_functions = import_analysis(filepath)
    suspicious_imports = {}
    for key, function_list in import_functions.items():
        for function in function_list:
            # print(function)
            if_in_blacklist = check_if_in_blacklist(function)
            if if_in_blacklist != None:
                suspicious_imports.setdefault(if_in_blacklist, [])
                suspicious_imports[if_in_blacklist].append(function)
    return suspicious_imports

def risk_score(suspicious_functions: dict)->tuple:
    """ """
    if len(suspicious_functions) == 0:
        return None
    res = 0
    risk_reasons = []
    for key, apis in suspicious_functions.items():
        res += RISK_WEIGHTS[key]
    for combo, reason in COMBO_BONUS.items():
        if combo[0] in suspicious_functions.keys() and combo[1] in suspicious_functions.keys():
            res += 5
            risk_reasons.append(reason)
    return (res, risk_reasons)
if __name__ == '__main__':
    filepath = 'rootkit.exe'
    dll_list = import_analysis(filepath)
    if dll_list != None:
        suspicious_imports = filter_suspicious_imports(dll_list)
        res = risk_score(suspicious_imports)
        print(res[0])
        if res == None:
            print("No suspicious imports detected")
        with open('test.json', 'w') as f:
            json.dump(suspicious_imports, f, indent = 3)
