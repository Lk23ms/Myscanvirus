# -*- coding: utf-8 -*-
"""Xóa file / kill process qua cmd.exe (subprocess shell=True)."""
import os
import re
import subprocess

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _dec(b):
    try:
        return b.decode("oem", errors="replace")
    except LookupError:
        return b.decode("utf-8", errors="replace")


def run_cmd(cmd, timeout=60):
    """Chạy lệnh cmd, trả {ok, code, stdout, stderr}."""
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True,
                           timeout=timeout, creationflags=NO_WINDOW)
        return {"ok": p.returncode == 0, "code": p.returncode,
                "stdout": _dec(p.stdout).strip(), "stderr": _dec(p.stderr).strip()}
    except subprocess.TimeoutExpired:
        return {"ok": False, "code": -1, "stdout": "", "stderr": "Hết thời gian chờ"}
    except Exception as e:
        return {"ok": False, "code": -1, "stdout": "", "stderr": str(e)}


def _fail(msg):
    return {"ok": False, "code": -1, "stdout": "", "stderr": msg}


def has_bad_char(s):
    """Ký tự có thể thoát khỏi dấu nháy trong cmd -> chặn (chống injection)."""
    return (not isinstance(s, str)) or (not s) or any(c in s for c in '"\r\n\0')


def _unsafe(path):
    """Chặn xóa ổ đĩa gốc, thư mục Windows, Program Files, thư mục user gốc."""
    p = os.path.normcase(os.path.abspath(path)).rstrip("\\/")
    if len(p) <= 2:
        return True
    prot = [os.environ.get(k, "") for k in
            ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "USERPROFILE")]
    prot.append(os.path.dirname(os.environ.get("USERPROFILE", "C:\\Users\\x")))
    for x in prot:
        x = os.path.normcase(x).rstrip("\\/")
        if x and (p == x or (x == os.path.normcase(os.environ.get("SystemRoot", "?")).rstrip("\\/")
                             and p.startswith(x + os.sep))):
            return True
    return False


def delete_file(path):
    if has_bad_char(path):
        return _fail("Đường dẫn không hợp lệ")
    if _unsafe(path):
        return _fail("Từ chối: đường dẫn hệ thống được bảo vệ")
    r = run_cmd(f'del /f /q "{path}"')
    r["ok"] = not os.path.exists(path)  # del hay trả code 0 dù thất bại
    return r


def delete_folder(path):
    if has_bad_char(path):
        return _fail("Đường dẫn không hợp lệ")
    if _unsafe(path):
        return _fail("Từ chối: thư mục hệ thống được bảo vệ")
    r = run_cmd(f'rmdir /s /q "{path}"')
    r["ok"] = not os.path.exists(path)
    return r


def delete_files(paths):
    done, failed = [], []
    for p in paths:
        (done if delete_file(p)["ok"] else failed).append(p)
    return {"ok": not failed, "code": 0 if not failed else 1,
            "stdout": f"Đã xóa {len(done)} file", "stderr": f"Lỗi {len(failed)} file" if failed else "",
            "deleted": done, "failed": failed}


def delete_small_files(folder, max_mb=1):
    """Xóa đệ quy file nhỏ hơn max_mb trong folder."""
    if has_bad_char(folder) or not os.path.isdir(folder):
        return _fail("Thư mục không hợp lệ")
    if _unsafe(folder):
        return _fail("Từ chối: thư mục hệ thống được bảo vệ")
    try:
        limit = float(max_mb) * 1024 * 1024
    except (TypeError, ValueError):
        return _fail("max_mb không hợp lệ")
    targets = []
    for dp, _dn, fn in os.walk(folder, onerror=lambda e: None):
        for f in fn:
            fp = os.path.join(dp, f)
            try:
                if os.path.getsize(fp) < limit:
                    targets.append(fp)
            except OSError:
                pass
    r = delete_files(targets)
    r["stdout"] = f"Đã xóa {len(r['deleted'])}/{len(targets)} file nhỏ"
    return r


def clear_recycle_bin():
    """Cần quyền Admin để dọn thùng rác của mọi user."""
    return run_cmd('rd /s /q "C:\\$Recycle.Bin"')


def kill_process(name):
    if not isinstance(name, str) or not re.fullmatch(r"[\w.\- ]{1,100}", name):
        return _fail("Tên process không hợp lệ")
    if "." not in name:
        name += ".exe"
    return run_cmd(f'taskkill /f /im "{name}"')
