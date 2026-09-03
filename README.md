# Malware Pre-Screener Tool

<!--
     Công cụ pre-screen file thực thi (PE) để hỗ trợ phân tích tĩnh
     ban đầu — không phải AV, không kết luận malware/clean tuyệt đối." -->

## ⚠️ Disclaimer

<!-- QUAN TRỌNG:
     - Tool này KHÔNG phải antivirus, không đưa ra verdict cuối cùng
     - risk_score chỉ mang tính tham khảo, dựa trên heuristic (blacklist import,
       entropy...), có thể false positive/false negative
     - entropy cao KHÔNG chắc chắn là packed/malicious
     - Khuyến cáo chỉ chạy trên môi trường cô lập (VM/sandbox), không chạy
       trực tiếp file nghi ngờ trên máy thật -->

## Tính năng

<!-- 
     - [ ] File info & hashing (MD5/SHA256, magic bytes, filetype)
     - [ ] PE header parsing (architecture, timestamp, suspicious flags)
     - [ ] Import analysis (suspicious imports theo category, risk score)
     - [ ] Section analysis (entropy, packed detection)
     - [ ] String extraction & IOC hunting (IP, URL, domain, registry, path) -->

## Yêu cầu / Cài đặt

<!-- Requirements thực tế theo import trong code:
     - Python 3.x
     - pefile (dùng trong mod2, mod3, mod4)
     Gợi ý: thêm requirements.txt rồi ghi `pip install -r requirements.txt` -->

```bash
pip install pefile
```

## Cách dùng

<!-- LƯU Ý: pre_screener.py hiện đang hardcode filepath = 'rootkit.exe',
     chưa nhận filepath qua CLI argument. Cần sửa argparse để thêm
     positional arg (ví dụ `filepath`) trước khi phần usage này chính xác.
     Sau khi sửa, usage sẽ dạng: -->

```bash
python pre_screener.py <filepath> --json output.json
python pre_screener.py <filepath> --quiet
```

| Flag | Mô tả |
|------|-------|
| `--json <file>` | Xuất kết quả dạng JSON thuần ra file |
| `--quiet` | Chỉ in 1-2 dòng summary + risk score |
| *(mặc định)* | In dạng bảng gọn, highlight phần đáng ngờ |

<!-- Ghi chú: hiện tool bắt buộc chọn 1 trong 2 (-q/-j) do mutually_exclusive_group,
     chưa có chế độ "in bảng gọn mặc định" như spec mô tả — cân nhắc bổ sung. -->

## Cấu trúc output

<!-- Convert thẳng từ spec PDF sang đây — bảng field/mô tả cho từng module.
     AI có thể giúp generate phần này từ code thật (tên field trong dict trả về),
     tự review lại cho khớp 100% với key thực tế trong res dict. -->

```json
{
  "file_info": {},
  "pe_header": {},
  "imports": {},
  "sections": {},
  "strings_iocs": {},
  "overall_risk_score": 0,
  "scan_timestamp": "..."
}
```

## Kiến trúc / Cấu trúc project

<!-- Tự viết ngắn gọn, ví dụ dạng tree:
mod1_fileinfo.py        # Module 1 - File info & hashing
mod2_PEparser.py         # Module 2 - PE header parsing
mod3_importanalysis.py   # Module 3 - Import analysis & risk scoring
mod4_sectionAnalysis.py  # Module 4 - Section entropy & packed detection
mod5_string_ioc.py       # Module 5 - String extraction & IOC hunting
pre_screener.py          # Orchestrator / CLI entrypoint -->

## Giới hạn hiện tại (Known limitations)

<!-- Tự viết, ví dụ:
     - Chỉ hỗ trợ PE (Windows), chưa parse ELF/Mach-O dù mod1 đã detect được filetype
     - Chưa xử lý file rỗng/không tồn tại ở tầng CLI (mod trả về None nhưng
       pre_screener.py chưa check None trước khi dùng tiếp)
     - min_len string extraction cố định = 4, chưa expose qua CLI -->

## License

<!-- Tự chọn -->
