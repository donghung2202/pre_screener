import mod1_fileinfo
import mod2_PEparser
import mod3_importanalysis
import mod4_sectionAnalysis
import mod5_string_ioc
import argparse
import json
import datetime

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='whether to write into json')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-q', '--quiet',action='store_true', help= 'If u just want to see the ouput in terminal')
    group.add_argument('-j', '--json',  help= 'result will be write')
    res = {
        "file_info": {...}, # Module 1
        "pe_header": {...}, # Module 2
        "imports": {...}, # Module 3
        "sections": {...}, # Module 4
        "strings_iocs": {...}, # Module 5
        "overall_risk_score": 0,
        "scan_timestamp": 0
    }
    filepath = 'rootkit.exe'
    res['file_info'] = mod1_fileinfo.extract_file_info(filepath)
    res['pe_header'] = mod2_PEparser.pe_parser(filepath)
    res['imports'] = mod3_importanalysis.filter_suspicious_imports(filepath)
    res['sections'] = mod4_sectionAnalysis.section_analysis(filepath=filepath)
    res['strings_iocs'] = mod5_string_ioc.extract_strings_and_iocs(filepath)
    res['scan_timestamp'] = datetime.datetime.now().isoformat()
    res['overall_risk_score'] = mod3_importanalysis.risk_score(res['imports'])

    args = parser.parse_args()
    if not args.quiet and not args.json:
        parser.error('At least one option must be entered ')
    if args.quiet:
        print(res)
    elif args.json:
        with open(args.json, 'w') as f:
            json.dump(res, f, indent = 4)


