# -*- coding: utf-8 -*-
"""Quét đệ quy thư mục, tìm dấu hiệu đáng ngờ trong file text."""
import os
import re
import sys

from signatures import _RAW, SEV_RANK

# Đuôi bỏ qua (media / nén / binary / tài liệu office / font)
SKIP_EXT = set(
    "mp4 mkv avi mov jpg png gif webp mp3 wav flac zip rar 7z exe dll sys bin iso "
    "msi pdf docx xlsx pptx ttf otf woff".split()
)
MAX_SIZE = 10 * 1024 * 1024  # 10MB
# Thư mục rác khổng lồ, gần như không chứa mã độc dạng text -> bỏ qua cho nhanh
SKIP_DIRS = {"node_modules", ".git", "__pycache__", "$recycle.bin", "system volume information",
             "winsxs", "cache", "code cache", "gpucache", "cache2", "service worker", ".gradle", ".m2", ".nuget"}

# Biên dịch regex 1 lần (không phân biệt hoa thường)
SIGS = [(i, re.compile(p, re.I), s, c, d) for (i, p, s, c, d) in _RAW]

# Bỏ qua chính thư mục của tool (tránh tự báo động vì chứa signature)
if getattr(sys, "frozen", False):
    SELF_DIR = os.path.normcase(os.path.dirname(sys.executable))
else:
    SELF_DIR = os.path.normcase(os.path.dirname(os.path.abspath(__file__)))


def _decode(data):
    """Trả về text hoặc None nếu file là binary."""
    if not data:
        return None
    # UTF-16 có BOM thì null byte là bình thường nên không loại
    has_bom = data[:2] in (b"\xff\xfe", b"\xfe\xff")
    if not has_bom and data.count(b"\x00") / len(data) > 0.02:
        return None
    text = None
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            text = data.decode(enc)
            break
        except (UnicodeDecodeError, UnicodeError):
            continue
    if not text:
        return None
    # Kiểm tra tỉ lệ ký tự in được trên mẫu 64KB đầu
    sample = text[:65536]
    ok = sum(1 for c in sample if c.isprintable() or c in "\t\r\n")
    if ok / len(sample) < 0.85:
        return None
    return text


def scan_file(path):
    """Quét 1 file, trả dict kết quả hoặc None nếu sạch/bỏ qua."""
    size = os.path.getsize(path)
    if size == 0 or size > MAX_SIZE:
        return None
    with open(path, "rb") as f:
        data = f.read()
    text = _decode(data)
    if text is None:
        return None

    hits = []
    for sid, rx, sev, cat, desc in SIGS:
        m = rx.search(text)  # 1 hit / signature / file
        if not m:
            continue
        s = m.start()
        snippet = " ".join(text[max(0, s - 100): s + 100].split())[:200]
        hits.append({
            "sig_id": sid, "severity": sev, "category": cat, "desc": desc,
            "line": text.count("\n", 0, s) + 1,
            "match": m.group(0)[:80], "snippet": snippet,
        })
    if not hits:
        return None
    top = max(hits, key=lambda h: SEV_RANK[h["severity"]])["severity"]
    return {"path": path, "name": os.path.basename(path), "severity": top,
            "hit_count": len(hits), "hits": hits}


def scan_folder(root, cancel, on_total, on_progress, on_hit):
    """Duyệt thư mục. cancel là threading.Event."""
    files = []
    for dp, dn, fn in os.walk(root, onerror=lambda e: None):
        if cancel.is_set():
            return
        dn[:] = [d for d in dn if d.lower() not in SKIP_DIRS]  # không đi vào thư mục rác
        if os.path.normcase(dp).startswith(SELF_DIR):
            continue
        on_progress(0, 0, f"đã thấy {len(files)} file — {dp}")  # báo tiến độ lúc liệt kê
        for f in fn:
            if os.path.splitext(f)[1].lower().lstrip(".") in SKIP_EXT:
                continue
            files.append(os.path.join(dp, f))
    total = len(files)
    on_total(total)
    for i, p in enumerate(files, 1):
        if cancel.is_set():
            break
        on_progress(i, total, p)
        try:
            r = scan_file(p)
        except (PermissionError, OSError):
            continue
        except Exception:  # lỗi lạ (regex, bộ nhớ...) thì bỏ qua file này
            continue
        if r:
            on_hit(r)
