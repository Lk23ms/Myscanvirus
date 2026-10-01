# -*- coding: utf-8 -*-
"""Database dấu hiệu: (id, regex, severity, category, mô tả)."""

C, H, M, L = "critical", "high", "medium", "low"

_RAW = [
    # ---- DISCORD ----
    ("DC01", r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+", C, "DISCORD", "URL webhook Discord (hay dùng để gửi dữ liệu trộm)"),
    ("DC02", r"api/webhooks/\d{17,20}", H, "DISCORD", "Đường dẫn api/webhooks/<id>"),
    ("DC03", r"Authorization['\"]?\s*[:=]\s*['\"]?(?:Bot|Bearer)\s+[\w.\-]{20,}", H, "DISCORD", "Header Authorization Bot/Bearer kèm token"),
    ("DC04", r"discord_desktop_core", H, "DISCORD", "Truy cập discord_desktop_core (inject Discord)"),
    ("DC05", r"Local\s*Storage[\\/]+leveldb", H, "DISCORD", "Đọc Local Storage/leveldb (nơi lưu token)"),
    ("DC06", r"Network[\\/]+Cookies", H, "DISCORD", "Đọc file Network/Cookies của trình duyệt"),
    # ---- FACEBOOK / TRÌNH DUYỆT ----
    ("FB01", r"[\"'\s;]c_user\b", H, "FACEBOOK", "Cookie c_user của Facebook"),
    ("FB02", r"\bdatr\b\s*[=:]", M, "FACEBOOK", "Cookie datr của Facebook"),
    ("FB03", r"[\"'\s;]xs=\d+%3A", H, "FACEBOOK", "Cookie xs của Facebook"),
    ("FB04", r"Login\s*Data", M, "FACEBOOK", "Đọc file Login Data (mật khẩu trình duyệt)"),
    ("FB05", r"Web\s*Data", L, "FACEBOOK", "Đọc file Web Data (autofill/thẻ)"),
    ("FB06", r"Chrome[\\/]+User\s*Data[\\/]+Default", H, "FACEBOOK", "Truy cập thư mục profile Chrome"),
    # ---- MINECRAFT ----
    ("MC01", r"launcher_profiles\.json", M, "MINECRAFT", "Đọc launcher_profiles.json"),
    ("MC02", r"launcher_accounts\.json", H, "MINECRAFT", "Đọc launcher_accounts.json (chứa tài khoản)"),
    ("MC03", r"accessToken", M, "MINECRAFT", "Chuỗi accessToken"),
    ("MC04", r"clientToken", M, "MINECRAFT", "Chuỗi clientToken"),
    ("MC05", r"refresh_token", M, "MINECRAFT", "Chuỗi refresh_token"),
    ("MC06", r"authserver\.mojang\.com", M, "MINECRAFT", "Gọi authserver.mojang.com"),
    # ---- STEAM / TELEGRAM / CRYPTO / ROBLOX ----
    ("ST01", r"\bssfn\w*", H, "STEAM", "File ssfn* của Steam"),
    ("ST02", r"loginusers\.vdf", H, "STEAM", "Đọc loginusers.vdf của Steam"),
    ("TG01", r"tdata[\\/]", H, "TELEGRAM", "Truy cập thư mục tdata của Telegram"),
    ("CR01", r"wallet\.dat", H, "CRYPTO", "Đọc wallet.dat (ví tiền mã hoá)"),
    ("CR02", r"MetaMask|nkbihfbeogaeaoehlefnkodbefgpgknn", H, "CRYPTO", "Tham chiếu ví MetaMask"),
    ("RB01", r"ROBLOSECURITY", C, "ROBLOX", "Cookie .ROBLOSECURITY"),
    # ---- STEALER ----
    ("SL01", r"\bgrabber\b", H, "STEALER", "Từ khoá grabber"),
    ("SL02", r"\bstealer\b", H, "STEALER", "Từ khoá stealer"),
    ("SL03", r"token[\s_\-]*grab", C, "STEALER", "Token grabber"),
    ("SL04", r"sendToWebhook", C, "STEALER", "Hàm sendToWebhook"),
    ("SL05", r"\bexfil\w*", H, "STEALER", "Từ khoá exfil (đánh cắp dữ liệu)"),
    ("SL06", r"c2[_\-]?server", C, "STEALER", "Máy chủ điều khiển c2_server"),
    # ---- MINER ----
    ("MN01", r"\bxmrig\b", C, "MINER", "Trình đào xmrig"),
    ("MN02", r"\bminerd\b", H, "MINER", "Trình đào minerd"),
    ("MN03", r"cpuminer", H, "MINER", "Trình đào cpuminer"),
    ("MN04", r"--donate-level", C, "MINER", "Tham số --donate-level của miner"),
    ("MN05", r"stratum\+(?:tcp|ssl)://", C, "MINER", "Giao thức stratum (mining pool)"),
    ("MN06", r"pool\.minexmr", C, "MINER", "Pool đào Monero minexmr"),
    # ---- PERSISTENCE ----
    ("PS01", r"schtasks(?:\.exe)?\s+/create", H, "PERSISTENCE", "Tạo scheduled task để bám máy"),
    ("PS02", r"reg(?:\.exe)?\s+add\s+[^\r\n]{0,120}CurrentVersion\\Run", H, "PERSISTENCE", "Ghi registry Run để tự khởi động"),
    ("PS03", r"Start\s*Menu[\\/]+Programs[\\/]+Startup", M, "PERSISTENCE", "Ghi vào thư mục Startup"),
    ("PS04", r"WScript\.Shell", M, "PERSISTENCE", "Dùng WScript.Shell"),
    ("PS05", r"CreateObject\s*\(", L, "PERSISTENCE", "Gọi CreateObject("),
    # ---- OBFUSCATION ----
    ("OB01", r"powershell(?:\.exe)?[^\r\n]{0,60}\s-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", C, "OBFUSCATION", "powershell -enc (lệnh mã hoá)"),
    ("OB02", r"-EncodedCommand", H, "OBFUSCATION", "Tham số -EncodedCommand"),
    ("OB03", r"AmsiScanBuffer", C, "OBFUSCATION", "Patch AmsiScanBuffer (né antivirus)"),
    ("OB04", r"Set-MpPreference[^\r\n]{0,60}-?Disable\w*", C, "OBFUSCATION", "Tắt Windows Defender"),
    ("OB05", r"fodhelper", C, "OBFUSCATION", "Bypass UAC qua fodhelper"),
    # ---- DYNAMIC EXEC ----
    ("DX01", r"\beval\s*\(", L, "DYNAMIC", "Gọi eval("),
    ("DX02", r"\bexec\s*\(", L, "DYNAMIC", "Gọi exec("),
    ("DX03", r"base64_decode", M, "DYNAMIC", "base64_decode"),
    ("DX04", r"FromBase64String", M, "DYNAMIC", "FromBase64String"),
    ("DX05", r"\batob\s*\(", L, "DYNAMIC", "Gọi atob("),
    ("DX06", r"fromCharCode", L, "DYNAMIC", "String.fromCharCode"),
    ("DX07", r"(?:0x[0-9a-f]{2}[,\s]*){20,}", M, "DYNAMIC", "Chuỗi hex dài"),
    ("DX08", r"[A-Za-z0-9+/]{200,}={0,2}", M, "DYNAMIC", "Chuỗi base64 dài (>200 ký tự)"),
    # ---- NETWORK ----
    ("NW01", r"raw\.githubusercontent\.com", L, "NETWORK", "Tải từ raw.githubusercontent.com"),
    ("NW02", r"pastebin\.com/raw", M, "NETWORK", "Tải từ pastebin raw"),
    ("NW03", r"cdn\.discordapp\.com/attachments", M, "NETWORK", "Tải file từ cdn.discordapp.com"),
    ("NW04", r"ngrok(?:-free)?\.(?:io|app|dev)", M, "NETWORK", "Tunnel ngrok"),
    ("NW05", r"api\.telegram\.org/bot\d+", H, "NETWORK", "Gửi dữ liệu qua bot Telegram"),
]

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
