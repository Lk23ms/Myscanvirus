# -*- coding: utf-8 -*-
"""Startup manager (Run / Startup folder / Task / Service) + tiện ích nguồn."""
import csv
import io
import json
import os
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from cleaner import run_cmd, has_bad_char


def base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


LOG_FILE = os.path.join(base_dir(), "onlysn_booter.log")
BACKUP_FILE = os.path.join(base_dir(), "onlysn_disabled.json")  # lưu entry đã tắt để bật lại
_lock = threading.Lock()

REG_KEYS = [
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
]


def startup_dirs():
    return [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp"),
    ]


def log(msg):
    try:
        with _lock, open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}\n")
    except OSError:
        pass


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _res(ok, msg="", code=0, stdout="", stderr=""):
    return {"ok": ok, "code": code, "stdout": stdout or msg, "stderr": stderr}


# ---------------- Backup entry đã disable ----------------
def _load_backup():
    try:
        with open(BACKUP_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def _save_backup(items):
    try:
        with _lock, open(BACKUP_FILE, "w", encoding="utf-8") as f:
            json.dump(items, f, ensure_ascii=False, indent=1)
    except OSError as e:
        log(f"Lỗi ghi backup: {e}")


def _backup_add(item):
    items = [i for i in _load_backup() if not (i["source"] == item["source"] and i["raw"] == item["raw"] and i["name"] == item["name"])]
    items.append(item)
    _save_backup(items)


def _backup_pop(source, raw, name):
    items = _load_backup()
    found = next((i for i in items if i["source"] == source and i["raw"] == raw and i["name"] == name), None)
    if found:
        items.remove(found)
        _save_backup(items)
    return found


# ---------------- Đánh dấu nghi ngờ ----------------
SUS_CMD = ["cmd /c", "cmd.exe /c", "wscript", "cscript", "mshta", "rundll32",
           "regsvr32", "certutil", "bitsadmin"]
SUS_EXT = {".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".scr", ".pif", ".bat", ".cmd", ".ps1"}
NAME_WORDS = ["updater", "svchost", "runtime", "java", "driver"]
PATH_RX = re.compile(r'([A-Za-z]:\\[^"|<>?*\r\n]*?\.(?:exe|bat|cmd|ps1|vbs|vbe|jse|js|wsf|hta|scr|pif|com|dll|lnk))', re.I)
PS_ENC_RX = re.compile(r"powershell[^\r\n]{0,60}\s-e(?:nc|ncodedcommand)?\b", re.I)
B64_RX = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
URL_RX = re.compile(r"https?://", re.I)
IP_RX = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _extract_path(cmd):
    m = PATH_RX.search(os.path.expandvars(cmd or ""))
    return m.group(1) if m else ""


def analyze(e):
    """Điền path, suspicious, reason cho entry."""
    cmd = e.get("command", "") or ""
    low = os.path.expandvars(cmd).lower()
    path = e.get("path") or _extract_path(cmd)
    e["path"] = path
    pl = path.lower()
    reasons = []

    if PS_ENC_RX.search(cmd):
        reasons.append("powershell -enc (lệnh mã hoá)")
    for k in SUS_CMD:
        if k in low:
            reasons.append(f"Command chứa '{k}'")
    # Thư mục dễ bị lợi dụng (bỏ qua với Startup folder vì nó nằm sẵn trong %APPDATA%)
    if path and e["source"] != "Startup":
        for tag, d in (("%TEMP%", os.environ.get("TEMP", "")), ("%APPDATA%", os.environ.get("APPDATA", "")),
                       ("%LOCALAPPDATA%", os.environ.get("LOCALAPPDATA", ""))):
            if d and pl.startswith(d.lower()):
                reasons.append(f"Path nằm trong {tag}")
        for tag in ("\\downloads\\", "\\users\\public", "recycle"):
            if tag in pl:
                reasons.append(f"Path chứa '{tag.strip(chr(92))}'")
    if path and not os.path.exists(path):
        reasons.append("Path không tồn tại (file đã bị xóa nhưng entry còn)")
    if os.path.splitext(pl)[1] in SUS_EXT:
        reasons.append(f"Đuôi file {os.path.splitext(pl)[1]}")
    if B64_RX.search(cmd):
        reasons.append("Chứa chuỗi base64 dài")
    if URL_RX.search(cmd):
        reasons.append("Chứa URL")
    if IP_RX.search(cmd):
        reasons.append("Chứa địa chỉ IP")
    # Tên giả mạo: tên hay bị bắt chước nhưng file không nằm ở thư mục tin cậy
    trusted = [os.environ.get(k, "").lower() for k in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)")]
    in_trusted = any(t and pl.startswith(t) for t in trusted)
    nm = e["name"].lower()
    for w in NAME_WORDS:
        if w in nm and not in_trusted:
            reasons.append(f"Tên chứa '{w}' nhưng không nằm ở thư mục tin cậy")
            break
    e["suspicious"] = bool(reasons)
    e["reason"] = "; ".join(dict.fromkeys(reasons))
    return e


def _entry(source, name, command, user, enabled, raw, path=""):
    return analyze({"source": source, "name": name, "command": command, "path": path,
                    "user": user, "enabled": enabled, "suspicious": False, "reason": "", "raw": raw})


# ---------------- Liệt kê ----------------
def _reg_list():
    out = []
    rx = re.compile(r"^\s{2,}(.+?)\s{4}(REG_\w+)\s{4}(.*)$")
    for key in REG_KEYS:
        r = run_cmd(f'reg query "{key}"')
        if not r["stdout"]:
            continue
        user = os.environ.get("USERNAME", "User") if key.startswith("HKCU") else "All users"
        for line in r["stdout"].splitlines():
            m = rx.match(line)
            if m:
                out.append(_entry("Run", m.group(1), m.group(3), user, True, key))
    return out


def _folder_list():
    out = []
    for i, d in enumerate(startup_dirs()):
        user = os.environ.get("USERNAME", "User") if i == 0 else "All users"
        try:
            names = os.listdir(d)
        except (OSError, PermissionError):
            continue
        for fn in names:
            if fn.lower() == "desktop.ini":
                continue
            full = os.path.join(d, fn)
            dis = fn.lower().endswith(".disabled")
            nm = fn[:-9] if dis else fn
            out.append(_entry("Startup", nm, full, user, not dis, full, path=full))
    return out


def _task_list():
    out, seen = [], set()
    r = run_cmd("schtasks /query /fo CSV /v", timeout=120)
    # Chỉ đúng với Windows tiếng Anh (cột Schedule Type = "At logon time"/"At system start up")
    for row in csv.reader(io.StringIO(r["stdout"])):
        if len(row) < 19 or row[1] == "TaskName":
            continue
        name, cmd, state, user, sched = row[1], row[8], row[11], row[14], row[18].lower()
        if not ("logon" in sched or "start up" in sched or "startup" in sched or "system start" in sched):
            continue
        if name in seen:
            continue
        seen.add(name)
        out.append(_entry("Task", name, cmd, user, state.strip().lower() != "disabled", name))
    return out


def _sc_qc(name):
    r = run_cmd(f'sc qc "{name}"', timeout=15)
    d = {"command": "", "user": "", "start": ""}
    for line in r["stdout"].splitlines():
        s = line.strip()
        if s.startswith("BINARY_PATH_NAME"):
            d["command"] = s.split(":", 1)[1].strip()
        elif s.startswith("SERVICE_START_NAME"):
            d["user"] = s.split(":", 1)[1].strip()
        elif s.startswith("START_TYPE"):
            d["start"] = s.split(":", 1)[1].strip()
    return d


def _service_list():
    out = []
    r = run_cmd('wmic service where "StartMode=\'Auto\'" get Name,PathName,StartName /format:csv', timeout=60)
    rows = [l for l in r["stdout"].splitlines() if l.strip()]
    if r["ok"] and len(rows) > 1:
        for row in csv.DictReader(rows):
            if row.get("Name"):
                out.append(_entry("Service", row["Name"], row.get("PathName", ""), row.get("StartName", ""), True, row["Name"]))
        return out
    # Fallback khi máy không còn wmic (Windows 11 mới): dùng sc
    q = run_cmd("sc query type= service state= all", timeout=60)
    names = re.findall(r"SERVICE_NAME:\s*(.+)", q["stdout"])
    with ThreadPoolExecutor(max_workers=8) as ex:
        for n, d in zip(names, ex.map(lambda x: _sc_qc(x.strip()), names)):
            if "AUTO_START" in d["start"]:
                out.append(_entry("Service", n.strip(), d["command"], d["user"], True, n.strip()))
    return out


def list_startup():
    entries = []
    for fn in (_reg_list, _folder_list, _task_list, _service_list):
        try:
            entries += fn()
        except Exception as e:  # 1 nguồn lỗi không làm hỏng cả danh sách
            log(f"Lỗi liệt kê {fn.__name__}: {e}")
    # Entry registry/service đã bị tắt bởi tool (lấy từ backup)
    for b in _load_backup():
        if b["source"] == "Service":
            d = _sc_qc(b["name"])
            entries.append(_entry("Service", b["name"], d["command"], d["user"], False, b["raw"]))
        else:
            entries.append(_entry("Run", b["name"], b.get("value", ""), "-", False, b["raw"]))
    return entries


# ---------------- Hành động ----------------
def _valid(source, name, raw):
    if has_bad_char(name) or has_bad_char(raw):
        return "Tham số không hợp lệ"
    if source == "Run" and raw not in REG_KEYS:
        return "Registry key không hợp lệ"
    if source == "Startup":
        d = os.path.normcase(os.path.dirname(raw))
        if d not in [os.path.normcase(x) for x in startup_dirs()]:
            return "File không nằm trong thư mục Startup"
    if source not in ("Run", "Startup", "Task", "Service"):
        return "Nguồn không hợp lệ"
    return ""


def _reg_get(key, name):
    r = run_cmd(f'reg query "{key}" /v "{name}"')
    m = re.search(r"\s(REG_\w+)\s{4}(.*)$", r["stdout"], re.M)
    return (m.group(1), m.group(2)) if m else None


def disable_startup(source, name, raw):
    try:
        err = _valid(source, name, raw)
        if err:
            return _res(False, stderr=err)
        if source == "Run":
            v = _reg_get(raw, name)
            if not v:
                return _res(False, stderr="Không đọc được giá trị registry")
            _backup_add({"source": "Run", "name": name, "raw": raw, "type": v[0], "value": v[1]})
            r = run_cmd(f'reg delete "{raw}" /v "{name}" /f')
            if not r["ok"]:
                _backup_pop("Run", raw, name)
        elif source == "Startup":
            if raw.lower().endswith(".disabled"):
                return _res(True, "Đã tắt từ trước")
            r = run_cmd(f'move /y "{raw}" "{raw}.disabled"')
        elif source == "Task":
            r = run_cmd(f'schtasks /change /tn "{raw}" /disable')
        else:
            _backup_add({"source": "Service", "name": name, "raw": raw})
            r = run_cmd(f'sc config "{raw}" start= disabled')
            if not r["ok"]:
                _backup_pop("Service", raw, name)
        log(f"DISABLE {source} '{name}' ({raw}) -> {r['ok']} {r['stderr'] or r['stdout']}")
        return r
    except Exception as e:
        log(f"DISABLE lỗi: {e}")
        return _res(False, stderr=str(e))


def enable_startup(source, name, raw):
    try:
        err = _valid(source, name, raw)
        if err:
            return _res(False, stderr=err)
        if source == "Run":
            b = _backup_pop("Run", raw, name)
            if not b:
                return _res(False, stderr="Không có bản sao lưu để khôi phục")
            val = b["value"].replace('"', '\\"')
            r = run_cmd(f'reg add "{raw}" /v "{name}" /t {b["type"]} /d "{val}" /f')
            if not r["ok"]:
                _backup_add(b)
        elif source == "Startup":
            if not raw.lower().endswith(".disabled"):
                return _res(True, "Đang bật sẵn")
            r = run_cmd(f'move /y "{raw}" "{raw[:-9]}"')
        elif source == "Task":
            r = run_cmd(f'schtasks /change /tn "{raw}" /enable')
        else:
            r = run_cmd(f'sc config "{raw}" start= auto')
            if r["ok"]:
                _backup_pop("Service", raw, name)
        log(f"ENABLE {source} '{name}' ({raw}) -> {r['ok']} {r['stderr'] or r['stdout']}")
        return r
    except Exception as e:
        log(f"ENABLE lỗi: {e}")
        return _res(False, stderr=str(e))


def delete_startup(source, name, raw):
    try:
        err = _valid(source, name, raw)
        if err:
            return _res(False, stderr=err)
        if source == "Run":
            if _backup_pop("Run", raw, name):  # entry đã tắt: chỉ cần xóa backup
                r = _res(True, "Đã xóa entry (đã tắt từ trước)")
            else:
                r = run_cmd(f'reg delete "{raw}" /v "{name}" /f')
        elif source == "Startup":
            r = run_cmd(f'del /f /q "{raw}"')
            r["ok"] = not os.path.exists(raw)
        elif source == "Task":
            r = run_cmd(f'schtasks /delete /tn "{raw}" /f')
        else:
            r = run_cmd(f'sc delete "{raw}"')
            if r["ok"]:
                _backup_pop("Service", raw, name)
        log(f"DELETE {source} '{name}' ({raw}) -> {r['ok']} {r['stderr'] or r['stdout']}")
        return r
    except Exception as e:
        log(f"DELETE lỗi: {e}")
        return _res(False, stderr=str(e))


def open_location(path):
    if has_bad_char(path) or not os.path.exists(path):
        return _res(False, stderr="Đường dẫn không tồn tại")
    r = run_cmd(f'explorer /select,"{path}"')
    r["ok"] = True  # explorer luôn trả code 1 dù mở được
    log(f"OPEN {path}")
    return r


# ---------------- Tiện ích nguồn ----------------
def _delay(d):
    try:
        return max(0, min(int(d), 3600))
    except (TypeError, ValueError):
        return 0


def _power(label, cmd):
    r = run_cmd(cmd, timeout=15)
    log(f"POWER {label}: {cmd} -> {r['ok']} {r['stderr'] or r['stdout']}")
    return r


def restart(delay=0):
    return _power(f"restart({_delay(delay)}s)", f"shutdown /r /t {_delay(delay)} /f")


def shutdown(delay=0):
    return _power(f"shutdown({_delay(delay)}s)", f"shutdown /s /t {_delay(delay)} /f")


def sleep():
    return _power("sleep", "rundll32.exe powrprof.dll,SetSuspendState 0,1,0")


def hibernate():
    return _power("hibernate", "shutdown /h")


def lock():
    return _power("lock", "rundll32.exe user32.dll,LockWorkStation")


def cancel_shutdown():
    return _power("cancel", "shutdown /a")


def logoff():
    return _power("logoff", "shutdown /l")
