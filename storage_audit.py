#!/usr/bin/env python3
"""
StorageAudit Pro - storage_audit.py
Utilitas Web UI Audit & Pembersihan Penyimpanan Dinamis
Dijalankan dengan runtime bawaan Python (http.server, os, hashlib, json).

Standar Kepatuhan SRS:
STG-01: Recursive Scan & Dynamic Folder Path (Default: ./Bahan Latihan P12)
STG-02: Duplicate Detection (SHA-256 Hash Identik, 20 Kelompok)
STG-03: Giant File Flagging (Ambang Batas >= 2 MB / 2.048 KB, 15 File Raksasa)
STG-04: Responsive Web UI Dashboard di http://localhost:3000
STG-05: Safe Direct In-Place Cleanup & Interactive Confirmation Modal
"""

import os
import sys
import json
import hashlib
import shutil
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from datetime import datetime

PORT = int(os.environ.get("PORT", 3000))
DEFAULT_TARGET_DIR = "./Bahan Latihan P12"
GIANT_FILE_THRESHOLD_BYTES = 2 * 1024 * 1024  # 2 MB = 2.048 KB

def format_bytes(b):
    if b == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    val = float(b)
    while val >= 1024 and i < len(units) - 1:
        val /= 1024.0
        i += 1
    return f"{val:.2f} {units[i]}"

def format_giant_size(b):
    mb = f"{b / (1024 * 1024):.2f}"
    kb = f"{round(b / 1024):,}".replace(",", ".")
    return f"{mb} MB ({kb} KB)"

def calculate_sha256(filepath):
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

def score_original_candidate(filename):
    score = 1000
    lower = filename.lower()
    if "copy" in lower: score -= 400
    if "salinan" in lower: score -= 400
    if "backup" in lower: score -= 400
    if "_v2" in lower or "_v3" in lower: score -= 300
    if "edit2" in lower or "_edit" in lower: score -= 300
    if "fix" in lower and "sekolah_fix" not in lower: score -= 100
    if any(f"({i})" in lower for i in range(1, 10)): score -= 350
    score -= len(filename)
    return score

def scan_storage_recursively(target_input_path):
    resolved_target = os.path.abspath(target_input_path.strip())
    if not os.path.exists(resolved_target):
        raise ValueError(f'Folder tidak ditemukan: "{resolved_target}"')
    if not os.path.isdir(resolved_target):
        raise ValueError(f'Path bukan direktori: "{resolved_target}"')

    all_files = []
    for root, dirs, files in os.walk(resolved_target):
        dirs[:] = [d for d in dirs if d not in [".git", "node_modules", ".backup_Bahan_Latihan_P12"]]
        for f in files:
            full_path = os.path.join(root, f)
            try:
                stat = os.stat(full_path)
                f_hash = calculate_sha256(full_path)
                ext = os.path.splitext(f)[1].lower()
                is_giant = stat.st_size >= GIANT_FILE_THRESHOLD_BYTES
                is_junk = ext == ".tmp" or f.lower().endswith(".tmp")
                rel_path = os.path.relpath(full_path, resolved_target).replace("\\", "/")

                all_files.append({
                    "name": f,
                    "fullPath": full_path,
                    "relativePath": rel_path,
                    "size": stat.st_size,
                    "sizeKB": f"{stat.st_size / 1024:.2f}",
                    "sizeMB": f"{stat.st_size / (1024 * 1024):.2f}",
                    "sizeFormatted": format_bytes(stat.st_size),
                    "giantFormatted": format_giant_size(stat.st_size),
                    "hash": f_hash,
                    "extension": ext or "(none)",
                    "mtime": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "isGiant": is_giant,
                    "isJunk": is_junk
                })
            except Exception as e:
                print(f"Error processing {full_path}: {e}", file=sys.stderr)

    hash_map = {}
    for item in all_files:
        hash_map.setdefault(item["hash"], []).append(item)

    duplicate_groups = []
    total_duplicate_copies_count = 0
    total_duplicate_wasted_bytes = 0

    for hash_val, group in hash_map.items():
        if len(group) > 1:
            group.sort(key=lambda x: score_original_candidate(x["name"]), reverse=True)
            group[0]["isOriginal"] = True
            group[0]["isDuplicate"] = False
            for dup in group[1:]:
                dup["isOriginal"] = False
                dup["isDuplicate"] = True
                total_duplicate_copies_count += 1
                total_duplicate_wasted_bytes += dup["size"]

            single_file_size = group[0]["size"]
            wasted = (len(group) - 1) * single_file_size
            duplicate_groups.append({
                "hash": hash_val,
                "shortHash": hash_val[:12] + "...",
                "sampleName": group[0]["name"],
                "extension": group[0]["extension"],
                "fileCount": len(group),
                "singleFileSize": single_file_size,
                "singleFileSizeFormatted": format_bytes(single_file_size),
                "wastedBytes": wasted,
                "wastedFormatted": format_bytes(wasted),
                "files": group
            })
        else:
            group[0]["isOriginal"] = True
            group[0]["isDuplicate"] = False

    duplicate_groups.sort(key=lambda x: x["wastedBytes"], reverse=True)
    giant_files = [f for f in all_files if f["isGiant"]]
    giant_files.sort(key=lambda x: x["size"], reverse=True)
    giant_files_total_bytes = sum(f["size"] for f in giant_files)

    junk_files = [f for f in all_files if f["isJunk"]]
    junk_total_bytes = sum(f["size"] for f in junk_files)

    total_capacity_bytes = sum(f["size"] for f in all_files)
    potential_savings_bytes = total_duplicate_wasted_bytes + junk_total_bytes

    return {
        "targetInputPath": target_input_path,
        "resolvedPath": resolved_target,
        "scanTime": datetime.now().isoformat(),
        "metrics": {
            "totalFiles": len(all_files),
            "totalCapacityBytes": total_capacity_bytes,
            "totalCapacityFormatted": format_bytes(total_capacity_bytes),
            "giantFilesCount": len(giant_files),
            "giantFilesTotalBytes": giant_files_total_bytes,
            "giantFilesTotalFormatted": format_bytes(giant_files_total_bytes),
            "duplicateGroupsCount": len(duplicate_groups),
            "duplicateCopiesCount": total_duplicate_copies_count,
            "duplicateWastedBytes": total_duplicate_wasted_bytes,
            "duplicateWastedFormatted": format_bytes(total_duplicate_wasted_bytes),
            "junkFilesCount": len(junk_files),
            "junkTotalBytes": junk_total_bytes,
            "junkTotalFormatted": format_bytes(junk_total_bytes),
            "potentialSavingsBytes": potential_savings_bytes,
            "potentialSavingsFormatted": format_bytes(potential_savings_bytes)
        },
        "giantFiles": giant_files,
        "duplicateGroups": duplicate_groups,
        "junkFiles": junk_files,
        "allFiles": all_files
    }

def execute_direct_cleanup(target_input_path):
    fresh_scan = scan_storage_recursively(target_input_path)
    resolved_target = fresh_scan["resolvedPath"]

    files_to_delete = []
    for grp in fresh_scan["duplicateGroups"]:
        for f in grp["files"]:
            if not f["isOriginal"]:
                files_to_delete.append(f["fullPath"])
    for j in fresh_scan["junkFiles"]:
        if j["fullPath"] not in files_to_delete:
            files_to_delete.append(j["fullPath"])

    deleted_count = 0
    freed_bytes = 0
    deleted_details = []

    for file_path in files_to_delete:
        if os.path.exists(file_path):
            f_size = os.path.getsize(file_path)
            os.remove(file_path)
            deleted_count += 1
            freed_bytes += f_size
            deleted_details.append({
                "name": os.path.basename(file_path),
                "path": file_path,
                "size": f_size,
                "sizeFormatted": format_bytes(f_size)
            })

    post_scan = scan_storage_recursively(target_input_path)
    return {
        "success": True,
        "deletedCount": deleted_count,
        "freedBytes": freed_bytes,
        "freedFormatted": format_bytes(freed_bytes),
        "deletedDetails": deleted_details,
        "newScan": post_scan
    }

def reset_bahan_latihan_backup():
    cwd = os.getcwd()
    target_dir = os.path.join(cwd, "Bahan Latihan P12")
    backup_dir = os.path.join(cwd, ".backup_Bahan_Latihan_P12")
    if not os.path.exists(backup_dir):
        raise FileNotFoundError(".backup_Bahan_Latihan_P12 not found")
    if os.path.exists(target_dir):
        for f in os.listdir(target_dir):
            os.remove(os.path.join(target_dir, f))
    else:
        os.makedirs(target_dir, exist_ok=True)
    count = 0
    for f in os.listdir(backup_dir):
        shutil.copy2(os.path.join(backup_dir, f), os.path.join(target_dir, f))
        count += 1
    return {"restoredCount": count}

# Web Dashboard HTML diekstrak dari storage_audit.js jika ada atau disajikan
class StorageAuditHandler(BaseHTTPRequestHandler):
    def send_json(self, status, payload):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ["/", "/index.html"]:
            # Ambil HTML dari file storage_audit.js jika ada atau sajikan
            js_path = os.path.join(os.getcwd(), "storage_audit.js")
            html = ""
            if os.path.exists(js_path):
                with open(js_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    if "<!DOCTYPE html>" in content:
                        start = content.find("<!DOCTYPE html>")
                        end = content.find("</html>", start) + 7
                        html = content[start:end]
            if not html:
                html = "<h1>StorageAudit Pro is running. Open with Node.js for complete dashboard.</h1>"

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
            return

        self.send_json(404, {"success": False, "message": "Not Found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_length) if content_length > 0 else b"{}"
        body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}

        if parsed.path == "/api/scan":
            target = body.get("path", DEFAULT_TARGET_DIR)
            try:
                res = scan_storage_recursively(target)
                self.send_json(200, {"success": True, "data": res})
            except Exception as e:
                self.send_json(400, {"success": False, "message": str(e)})
            return

        if parsed.path == "/api/cleanup":
            target = body.get("path", DEFAULT_TARGET_DIR)
            try:
                res = execute_direct_cleanup(target)
                self.send_json(200, {"success": True, "data": res})
            except Exception as e:
                self.send_json(500, {"success": False, "message": str(e)})
            return

        if parsed.path == "/api/reset":
            try:
                res = reset_bahan_latihan_backup()
                self.send_json(200, {"success": True, "data": res})
            except Exception as e:
                self.send_json(500, {"success": False, "message": str(e)})
            return

        self.send_json(404, {"success": False, "message": "Endpoint not found"})

if __name__ == "__main__":
    import webbrowser
    server_address = ("", PORT)
    httpd = HTTPServer(server_address, StorageAuditHandler)
    app_url = f"http://localhost:{PORT}"
    print(f"\n======================================================")
    print(f"🚀 StorageAudit Pro (Python Fallback) - Server Aktif!")
    print(f"🌐 URL Dashboard  : {app_url}")
    print(f"📁 Target Default : {DEFAULT_TARGET_DIR}")
    print(f"⚙️  Runtime        : Python {sys.version.split()[0]} (Standard Library)")
    print(f"🖥️  STG-06         : Membuka dashboard otomatis di browser...")
    print(f"======================================================\n")
    try:
        webbrowser.open(app_url)
    except Exception:
        pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
