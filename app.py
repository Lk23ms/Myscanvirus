# -*- coding: utf-8 -*-
"""OnlySn Studio — Threat Scanner & Booter. Flask localhost:5050."""
import csv
import io
import json
import logging
import os
import queue
import sys
import threading
import time
import webbrowser
from datetime import datetime

import flask.cli
from flask import Flask, Response, jsonify, render_template, request

import booter
import cleaner
import scanner

flask.cli.show_server_banner = lambda *a, **k: None  # ẩn banner Flask
logging.getLogger("werkzeug").setLevel(logging.ERROR)  # ẩn log werkzeug

PORT = 5050
HOST = "127.0.0.1"


def resource_dir():
    # Khi đóng gói PyInstaller, template nằm trong _MEIPASS
    return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))


app = Flask(__name__, template_folder=os.path.join(resource_dir(), "templates"))

lock = threading.RLock()
clients = []  # mỗi client SSE 1 queue riêng
cancel_evt = threading.Event()
state = {
    "running": False,
    "progress": {"current": 0, "total": 0, "file": ""},
    "results": [],
    "start_time": None,
    "target": "",
}
booter_state = {"busy": False}  # state booter riêng, tách khỏi state quét
booter_lock = threading.Lock()


# ---------------- Bảo vệ localhost ----------------
@app.before_request
def guard():
    # Chặn DNS rebinding + CSRF từ website khác gọi vào localhost
    if request.host.split(":")[0] not in ("127.0.0.1", "localhost"):
        return jsonify(ok=False, error="forbidden"), 403
    if request.method == "POST" and request.headers.get("X-Requested-With") != "onlysn":
        return jsonify(ok=False, error="forbidden"), 403


# ---------------- SSE ----------------
def broadcast(ev, data):
    with lock:
        for q in clients:
            q.put((ev, data))


def sse(ev, data):
    return f"event: {ev}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def snapshot():
    with lock:
        return {"running": state["running"], "progress": dict(state["progress"]),
                "results": list(state["results"]), "target": state["target"]}


@app.route("/api/scan/events")
def scan_events():
    q = queue.Queue()
    with lock:
        clients.append(q)
        snap = snapshot()

    def gen():
        try:
            yield sse("snapshot", snap)
            while True:
                try:
                    ev, data = q.get(timeout=15)
                    yield sse(ev, data)
                except queue.Empty:
                    yield ": ping\n\n"  # giữ kết nối
        finally:
            with lock:
                if q in clients:
                    clients.remove(q)

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------- Quét ----------------
def scan_worker(path):
    last = [0.0]

    def on_total(n):
        with lock:
            state["progress"]["total"] = n
        broadcast("total", {"total": n})

    def on_progress(i, n, fp):
        with lock:
            state["progress"].update(current=i, total=n, file=fp)
        now = time.time()
        if now - last[0] > 0.1 or (n > 0 and i == n):  # giới hạn tần suất gửi
            last[0] = now
            broadcast("progress", {"current": i, "total": n, "file": fp})

    def on_hit(r):
        with lock:
            state["results"].append(r)
        broadcast("hit", r)

    err = ""
    try:
        scanner.scan_folder(path, cancel_evt, on_total, on_progress, on_hit)
    except Exception as e:
        err = str(e)
    with lock:
        state["running"] = False
        elapsed = round(time.time() - state["start_time"], 1)
        n = len(state["results"])
    broadcast("done", {"cancelled": cancel_evt.is_set(), "elapsed": elapsed,
                       "hit_count": n, "error": err})


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan/start", methods=["POST"])
def scan_start():
    path = (request.get_json(silent=True) or {}).get("path", "").strip().strip('"')
    if not path or not os.path.isdir(path):
        return jsonify(ok=False, error="Đường dẫn không phải thư mục hợp lệ"), 400
    with lock:
        if state["running"]:
            return jsonify(ok=False, error="Đang quét rồi"), 409
        cancel_evt.clear()
        state.update(running=True, results=[], start_time=time.time(), target=path,
                     progress={"current": 0, "total": 0, "file": ""})
    broadcast("snapshot", snapshot())
    threading.Thread(target=scan_worker, args=(path,), daemon=True).start()
    return jsonify(ok=True)


@app.route("/api/scan/cancel", methods=["POST"])
def scan_cancel():
    cancel_evt.set()
    return jsonify(ok=True)


@app.route("/api/scan/status")
def scan_status():
    with lock:
        return jsonify(running=state["running"], progress=state["progress"],
                       hit_count=len(state["results"]))


@app.route("/api/info")
def info():
    with lock:
        return jsonify(target=state["target"], running=state["running"],
                       hit_count=len(state["results"]), admin=booter.is_admin())


# ---------------- Xuất log ----------------
def build_export(fmt, results, target):
    if fmt == "json":
        return json.dumps(results, ensure_ascii=False, indent=2), "application/json; charset=utf-8"
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["Path", "Name", "Severity", "HitCount", "Categories", "Descriptions", "Lines", "Snippets"])
        for r in results:
            h = r["hits"]
            w.writerow([r["path"], r["name"], r["severity"], r["hit_count"],
                        "|".join(sorted({x["category"] for x in h})),
                        " | ".join(x["desc"] for x in h),
                        ",".join(str(x["line"]) for x in h),
                        " || ".join(x["snippet"] for x in h)])
        return "\ufeff" + buf.getvalue(), "text/csv; charset=utf-8"  # BOM để Excel đọc đúng tiếng Việt
    lines = ["OnlySn Studio — Báo cáo quét", f"Thời gian : {datetime.now():%Y-%m-%d %H:%M:%S}",
             f"Thư mục   : {target}", f"File nghi ngờ: {len(results)}", "=" * 70]
    for r in results:
        lines.append(f"\n[{r['severity'].upper()}] {r['path']}")
        for x in r["hits"]:
            lines.append(f"  - ({x['category']}) {x['desc']} | dòng {x['line']}")
            lines.append(f"      {x['snippet']}")
    return "\n".join(lines), "text/plain; charset=utf-8"


@app.route("/api/log/export", methods=["POST"])
def log_export():
    fmt = (request.get_json(silent=True) or {}).get("format", "txt")
    if fmt not in ("txt", "csv", "json"):
        return jsonify(ok=False, error="Định dạng không hỗ trợ"), 400
    with lock:
        results, target = list(state["results"]), state["target"]
    body, mime = build_export(fmt, results, target)
    fname = f"onlysn_report_{datetime.now():%Y%m%d_%H%M%S}.{fmt}"
    return Response(body, mimetype=mime.split(";")[0],
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


# ---------------- Dọn dẹp ----------------
def drop_results(pred):
    with lock:
        state["results"] = [r for r in state["results"] if not pred(r["path"])]


def jbody():
    return request.get_json(silent=True) or {}


@app.route("/api/clean/file", methods=["POST"])
def clean_file():
    p = jbody().get("path", "")
    r = cleaner.delete_file(p)
    if r["ok"]:
        drop_results(lambda x: x == p)
    return jsonify(r)


@app.route("/api/clean/folder", methods=["POST"])
def clean_folder():
    p = jbody().get("path", "")
    r = cleaner.delete_folder(p)
    if r["ok"]:
        pre = os.path.normcase(p).rstrip("\\/") + os.sep
        drop_results(lambda x: os.path.normcase(x).startswith(pre))
    return jsonify(r)


@app.route("/api/clean/all", methods=["POST"])
def clean_all():
    with lock:
        paths = [r["path"] for r in state["results"]]
    r = cleaner.delete_files(paths)
    done = set(r["deleted"])
    drop_results(lambda x: x in done)
    return jsonify(r)


@app.route("/api/clean/small", methods=["POST"])
def clean_small():
    b = jbody()
    r = cleaner.delete_small_files(b.get("folder", ""), b.get("max_mb", 1))
    if r.get("deleted"):
        done = set(r["deleted"])
        drop_results(lambda x: x in done)
    return jsonify(r)


@app.route("/api/clean/recycle", methods=["POST"])
def clean_recycle():
    return jsonify(cleaner.clear_recycle_bin())


@app.route("/api/clean/kill", methods=["POST"])
def clean_kill():
    return jsonify(cleaner.kill_process(jbody().get("name", "")))


# ---------------- Booter ----------------
@app.route("/api/booter/startup")
def booter_startup():
    with booter_lock:
        entries = booter.list_startup()
    return jsonify(ok=True, entries=entries, admin=booter.is_admin(),
                   suspicious=sum(1 for e in entries if e["suspicious"]))


def _entry_action(fn):
    b = jbody()
    with booter_lock:
        return jsonify(fn(b.get("source", ""), b.get("name", ""), b.get("raw", "")))


@app.route("/api/booter/startup/disable", methods=["POST"])
def st_disable():
    return _entry_action(booter.disable_startup)


@app.route("/api/booter/startup/enable", methods=["POST"])
def st_enable():
    return _entry_action(booter.enable_startup)


@app.route("/api/booter/startup/delete", methods=["POST"])
def st_delete():
    return _entry_action(booter.delete_startup)


@app.route("/api/booter/startup/open", methods=["POST"])
def st_open():
    return jsonify(booter.open_location(jbody().get("path", "")))


@app.route("/api/booter/restart", methods=["POST"])
def b_restart():
    return jsonify(booter.restart(jbody().get("delay", 0)))


@app.route("/api/booter/shutdown", methods=["POST"])
def b_shutdown():
    return jsonify(booter.shutdown(jbody().get("delay", 0)))


@app.route("/api/booter/sleep", methods=["POST"])
def b_sleep():
    return jsonify(booter.sleep())


@app.route("/api/booter/hibernate", methods=["POST"])
def b_hibernate():
    return jsonify(booter.hibernate())


@app.route("/api/booter/lock", methods=["POST"])
def b_lock():
    return jsonify(booter.lock())


@app.route("/api/booter/logoff", methods=["POST"])
def b_logoff():
    return jsonify(booter.logoff())


@app.route("/api/booter/cancel", methods=["POST"])
def b_cancel():
    return jsonify(booter.cancel_shutdown())


if __name__ == "__main__":
    threading.Timer(1.2, lambda: webbrowser.open(f"http://{HOST}:{PORT}")).start()
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
