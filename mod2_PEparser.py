import pefile
import logging
import os, json
from datetime import datetime, timezone
import time
logging.basicConfig(level=logging.ERROR)


def pe_parser(filepath: str):
    dic = {}
    pe = None
    try:
        pe = pefile.PE(filepath)
        dic['magic_bytes'] = pe.DOS_HEADER.e_magic.to_bytes(2, 'little').decode()
        dic['signature_bytes'] = pe.NT_HEADERS.Signature.to_bytes(4, 'little').decode()
        dic['is_valid_pe'] = True
        dic['architecture'] = 'PE32' if hex(pe.OPTIONAL_HEADER.Magic) == '0x10b' else 'PE32+'

        dic['number_of_sections'] = pe.FILE_HEADER.NumberOfSections
        dic['characteristics'] = pe.FILE_HEADER.Characteristics
        dic['suspicious_flags'] = []
        # kiem tra so luong section
        if dic['number_of_sections'] < 2 or dic['number_of_sections'] > 8:
            dic['suspicious_flags'].append('Number of sections')
        # kiem tra timestamp
        timestamp = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, timezone.utc)
        dic['compile_timestamp'] = timestamp.isoformat()
        if pe.FILE_HEADER.TimeDateStamp == 0:
            dic['suspicious_flags'].append('TimeDateStamp is equals to ZERO')
        elif timestamp > datetime.now(timezone.utc):
            dic['suspicious_flags'].append('TimeDateStamp is not valid as it exceeds current time')

        # kiem tra co trong section va section co strange name
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        IMAGE_SCN_MEM_EXECUTE = 0x20000000
        COMMON_SECTION_NAMES = {
            '.text',      # code thực thi
            '.data',      # dữ liệu global có khởi tạo (initialized data)
            '.rdata',     # dữ liệu chỉ đọc (read-only data), VD: string literal, import table
            '.bss',       # dữ liệu chưa khởi tạo (uninitialized data)
            '.rsrc',      # resource: icon, dialog, version info, string table...
            '.reloc',     # base relocation table (dùng khi load ở địa chỉ khác ImageBase)
            '.idata',     # import table (1 số compiler tách riêng thay vì gộp vào .rdata)
            '.edata',     # export table (thường có ở DLL)
            '.pdata',     # exception handling data (chủ yếu x64)
            '.tls',       # Thread Local Storage
            '.debug',     # debug info (thường bị strip ở release build)
            '.didat',     # delay-load import table
        }
        for section in pe.sections:
            if entry_point >= section.VirtualAddress and entry_point <= (section.VirtualAddress + section.Misc_VirtualSize):
                is_executable = bool(section.Characteristics & IMAGE_SCN_MEM_EXECUTE)
                if is_executable == False:
                    dic['suspicious_flags'].append('Entry point to non-execute flag section')
            section_name = section.Name.decode().rstrip('\x00')
            if section_name not in COMMON_SECTION_NAMES:
                dic['suspicious_flags'].append(f'Section {section_name} is not a common section name ??')

    except pefile.PEFormatError as e:
        logging.error(e)
        return None
    except FileNotFoundError:
        logging.error(f'file {os.path.basename(filepath)} can\'t be found in {os.path.dirname(filepath)}')
        return None
    except OSError as e:
        logging.error(e)
        return None
    finally:
        if pe is not None:
            pe.close()
    return dic


if __name__ == '__main__':
    filepath = 'rootkit.exe'
    with open('res.json', 'w') as f:
        res = pe_parser(filepath)
        json.dump(res, f, indent = 3)
