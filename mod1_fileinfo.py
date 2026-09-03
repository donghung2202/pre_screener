import os
import logging
import hashlib
import json
logging.basicConfig(level = logging.DEBUG)

def check_filetype(data: bytes, MAGIC_BYTES: dict)-> tuple:
    for magic_byte in MAGIC_BYTES.keys():
        if data.startswith(magic_byte):
            return (MAGIC_BYTES[magic_byte], magic_byte)
    return ('Unknown File Type', b'')

def extract_file_info(filepath: str)->dict:
    dic = {}
    MAGIC_BYTES = {
        b'\x4D\x5A':               'PE (Windows EXE/DLL)',
        b'\x7F\x45\x4C\x46':       'ELF (Linux executable)',
        b'\xCA\xFE\xBA\xBE':       'Mach-O (macOS, 32-bit universal) / Java class',
        b'\xFE\xED\xFA\xCE':       'Mach-O (macOS, 32-bit)',
        b'\xFE\xED\xFA\xCF':       'Mach-O (macOS, 64-bit)',
        b'\x50\x4B\x03\x04':       'ZIP / JAR / DOCX / XLSX / APK (đều là ZIP container)',
        b'\x89\x50\x4E\x47':       'PNG',
        b'\xFF\xD8\xFF':           'JPEG',
        b'\x47\x49\x46\x38':       'GIF',
        b'\x25\x50\x44\x46':       'PDF',
        b'\x1F\x8B':                'GZIP',
        b'\x52\x61\x72\x21':       'RAR',
        b'\x37\x7A\xBC\xAF\x27\x1C': '7-Zip',
    }
    try:
        with open(filepath, 'rb') as f:
            dic['filename'] = os.path.basename(filepath)
            dic['filepath'] = os.path.abspath(filepath)
            dic['filesize'] = os.path.getsize(filepath)
            data = f.read()
            dic['md5_hash'] = hashlib.md5(data).hexdigest()
            dic['sha256_hash'] = hashlib.sha256(data).hexdigest()
            filetype = check_filetype(data, MAGIC_BYTES)
            dic['magic_bytes'] = filetype[1].decode()
            dic['filetype'] = filetype[0]

    except FileNotFoundError:
        logging.error("File not found, please check again!!!")
        return None
    except OSError as e:
        logging.error(e)
        return None

    return dic

if __name__ == '__main__':
    filepath = '/home/dnh/Documents/Week5_6/Day13/rootkit.exe'
    file_info = extract_file_info(filepath)
    with open('res.json', 'w') as f:
        json.dump(file_info, f, indent = 4)
    # if file_info != None:
    #     for key, value in file_info.items():
    #         print(f'{key}: {value}')