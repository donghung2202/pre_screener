import pefile
from collections import Counter
import math
import json
def cal_entropy(data: bytes):
    if not data:
        return 0
    freq = Counter(data)
    len_data = len(data)
    entropy = 0
    for value in freq.values():
        p = value / len_data
        entropy += -p * math.log2(p)
    return entropy
def high_entropy_sections(data: list[dict])-> dict:
    res = {}
    for dic in data:
        if dic['entropy'] >= 7.0:
            res[dic['name']] = dic['entropy']
    return res

def check_packed(section_analysis: dict):
    packed = False
    packed_confidence_note = []
    for section in section_analysis['sections']:
        if section['virtual_size'] > section['raw_size']:
            packed_confidence_note.append(f"{section['name']} has vir size > raw size")

    if len(section_analysis['sections']) <= 4:
        packed_confidence_note.append("Too few sections")
        packed = True
    if len(section_analysis['high_entropy_sections']) >= 2:
        packed_confidence_note.append(f"{len(section_analysis['high_entropy_sections'])} sections have high entropy")
        packed = True
    return (packed, packed_confidence_note)
def section_analysis(filepath: str):
    """
        sections : list of sections with their name, virtual_size, raw_size, entropy
        high_entropy_sections: list of sections have their entropy exceeding 7.5
        packed_warning: True or False if section is packed or not
        packed_confidence_note: entropy maybe high but not definite malware, look for other indicator

    """
    dic = {}
    try:
        pe = pefile.PE(filepath)
        for section in pe.sections:
            dic.setdefault('sections', [])
            k = {}
            k['name'] = section.Name.decode().rstrip('\x00')
            k['virtual_size'] = section.Misc_VirtualSize
            k['raw_size'] = section.SizeOfRawData
            data = section.get_data()
            entropy = cal_entropy(data)
            k['entropy'] = entropy
            dic['sections'].append(k)
        dic['high_entropy_sections'] = high_entropy_sections(dic['sections'])
        dic['packed'], dic['packed_confidence_note'] = check_packed(dic)
    except pefile.PEFormatError:
        print("PE format")
        return None
    except OSError as e:
        print(e)
    return dic
if __name__ == '__main__':
    filepath = 'rootkit.exe'
    dic = section_analysis(filepath)
    with open('test.json', 'w') as f:
        json.dump(dic, f, indent = 4)
