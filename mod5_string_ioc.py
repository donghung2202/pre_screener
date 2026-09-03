import re
import string

def find_ips(strings_list):
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    found = set()
    for s in strings_list:
        for match in ip_re.findall(s):
            octets = match.split(".")
            if all(0 <= int(o) <= 255 for o in octets):
                found.add(match)
    return sorted(found)


def find_urls(strings_list):
    url_re = re.compile(r"https?://[^\s\"'<>]+")
    found = set()
    for s in strings_list:
        found.update(url_re.findall(s))
    return sorted(found)


def find_domains(strings_list):
    domain_re = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|info|biz|io|ru|cn|xyz|top|club|online)\b"
    )
    found = set()
    for s in strings_list:
        found.update(domain_re.findall(s))
    return sorted(found)


def find_registry_paths(strings_list):
    reg_re = re.compile(r"HKEY_[A-Z_]+\\[^\s\"']+")
    found = set()
    for s in strings_list:
        found.update(reg_re.findall(s))
    return sorted(found)


def find_windows_paths(strings_list):
    path_re = re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*")
    found = set()
    for s in strings_list:
        found.update(path_re.findall(s))
    return sorted(found)
def extract_strings_and_iocs(filepath: str, min_len: int = 4) -> dict:
    with open(filepath, "rb") as f:
        data = f.read()

    # 1. Extract ASCII strings
    ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    ascii_matches = [m.decode("ascii") for m in ascii_pattern.findall(data)]

    # 2. Extract UTF-16-LE strings (mỗi ký tự ASCII cách nhau 1 byte \x00)
    unicode_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    unicode_raw = unicode_pattern.findall(data)
    unicode_matches = [m.decode("utf-16-le", errors="ignore") for m in unicode_raw]

    all_strings = ascii_matches + unicode_matches

    # 3. Dedup + sort theo độ dài, lấy top 50
    unique_sorted = sorted(set(all_strings), key=len, reverse=True)
    top_strings = unique_sorted[:50]

    # 4. Tìm IOC trên tập string đã extract (không quét lại raw bytes)
    ips_found = find_ips(all_strings)
    urls_found = find_urls(all_strings)
    domains_found = find_domains(all_strings)
    registry_paths_found = find_registry_paths(all_strings)
    windows_paths_found = find_windows_paths(all_strings)

    return {
        "top_strings": top_strings,
        "ascii_string_count": len(ascii_matches),
        "unicode_string_count": len(unicode_matches),
        "ips_found": ips_found,
        "urls_found": urls_found,
        "domains_found": domains_found,
        "registry_paths_found": registry_paths_found,
        "windows_paths_found": windows_paths_found,
    }