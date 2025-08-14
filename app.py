
import os
import sqlite3
import hashlib
import json
import mimetypes
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple

from flask import (
    Flask, render_template, request, redirect, url_for,
    send_from_directory, flash, abort
)
from werkzeug.utils import secure_filename

# Optional import: the app will still run and show a warning if yara isn't installed yet
try:
    import yara
except Exception as e:
    yara = None

APP_ROOT = Path(__file__).resolve().parent
UPLOAD_DIR = APP_ROOT / "uploads"
RULES_DIR = APP_ROOT / "rules"
INSTANCE_DIR = APP_ROOT / "instance"
DB_PATH = INSTANCE_DIR / "scanner.db"

MAX_CONTENT_LENGTH = 1024 * 1024 * 200  # 200 MB default

def create_app():
    app = Flask(__name__, instance_path=str(INSTANCE_DIR))
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret")
    app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_CONTENT_LENGTH", MAX_CONTENT_LENGTH))

    # Ensure directories exist
    for d in [UPLOAD_DIR, RULES_DIR, INSTANCE_DIR]:
        d.mkdir(parents=True, exist_ok=True)

    # DB init
    init_db()

    # Compile YARA at startup
    app.yara_rules = compile_yara_rules()

    @app.route("/")
    def index():
        files = query_db("""
            SELECT id, filename, sha256, size, mimetype, uploaded_at
            FROM files
            ORDER BY uploaded_at DESC
            LIMIT 50
        """)
        return render_template("index.html", files=files, yara_loaded=(app.yara_rules is not None))

    @app.route("/upload", methods=["POST"])
    def upload():
        if "file" not in request.files:
            flash("No file part", "error")
            return redirect(url_for("index"))

        f = request.files["file"]
        if f.filename == "":
            flash("No selected file", "error")
            return redirect(url_for("index"))

        filename = secure_filename(f.filename) or "upload.bin"
        # Stream to a temp file to hash safely
        tmp_path = UPLOAD_DIR / ("tmp_" + filename)
        with open(tmp_path, "wb") as tmp:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                tmp.write(chunk)

        sha256 = sha256_file(tmp_path)
        stored_path = UPLOAD_DIR / sha256

        # De-dup: move tmp to final if new, else delete tmp
        if not stored_path.exists():
            tmp_path.replace(stored_path)
        else:
            tmp_path.unlink(missing_ok=True)

        size = stored_path.stat().st_size
        mimetype, _ = mimetypes.guess_type(filename)
        mimetype = mimetype or "application/octet-stream"

        # Insert or get existing file row
        existing = query_db("SELECT id FROM files WHERE sha256 = ?", (sha256,), one=True)
        if existing:
            file_id = existing["id"]
            flash("File already exists; linking to existing record.", "info")
            return redirect(url_for("file_detail", file_id=file_id))

        # Insert file record
        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        execute_db("""
            INSERT INTO files (filename, sha256, size, mimetype, uploaded_at, stored_path)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (filename, sha256, size, mimetype, now, str(stored_path)))

        file_id = query_db("SELECT id FROM files WHERE sha256 = ?", (sha256,), one=True)["id"]

        # Scan with YARA
        matches = []
        if app.yara_rules is None and yara is None:
            flash("yara-python is not installed; skipping scan.", "warning")
        elif app.yara_rules is None:
            app.yara_rules = compile_yara_rules()
            if app.yara_rules is None:
                flash("No YARA rules found/compiled; skipping scan.", "warning")
            else:
                matches = run_yara(app.yara_rules, stored_path)
        else:
            matches = run_yara(app.yara_rules, stored_path)

        for rule_name in matches:
            execute_db("INSERT INTO matches (file_id, rule) VALUES (?, ?)", (file_id, rule_name))

        return redirect(url_for("file_detail", file_id=file_id))

    @app.route("/file/<int:file_id>")
    def file_detail(file_id: int):
        file_row = query_db("SELECT * FROM files WHERE id = ?", (file_id,), one=True)
        if not file_row:
            abort(404)

        matched_rules = {r["rule"] for r in query_db("SELECT rule FROM matches WHERE file_id = ?", (file_id,))}

        # Similarity: files that share at least one matched rule
        similar = []
        if matched_rules:
            # Fetch candidate files that share any rule (excluding this file)
            placeholders = ",".join("?" for _ in matched_rules)
            query = f"""
                SELECT DISTINCT f.id, f.filename, f.sha256, f.size, f.mimetype, f.uploaded_at
                FROM matches m
                JOIN files f ON f.id = m.file_id
                WHERE m.rule IN ({placeholders}) AND f.id != ?
            """
            candidates = query_db(query, (*matched_rules, file_id))
            # For each candidate, compute Jaccard similarity
            for c in candidates:
                crules = {r["rule"] for r in query_db("SELECT rule FROM matches WHERE file_id = ?", (c["id"],))}
                jaccard = jaccard_sim(matched_rules, crules)
                if jaccard > 0.0:
                    overlap = sorted(matched_rules & crules)
                    similar.append((c, jaccard, overlap))

            # Sort by similarity desc, then date desc
            similar.sort(key=lambda t: (t[1], t[0]["uploaded_at"]), reverse=True)

        return render_template(
            "file_detail.html",
            file=file_row,
            rules=sorted(matched_rules),
            similar=similar,
            yara_loaded=(app.yara_rules is not None)
        )

    @app.route("/files")
    def files_list():
        files = query_db("""
            SELECT id, filename, sha256, size, mimetype, uploaded_at
            FROM files
            ORDER BY uploaded_at DESC
        """)
        return render_template("files.html", files=files)

    @app.route("/download/<sha256>")
    def download(sha256: str):
        # Only allow download by sha256 and ensure it exists
        p = (UPLOAD_DIR / sha256).resolve()
        if not p.exists() or p.parent != UPLOAD_DIR.resolve():
            abort(404)
        # Send with original filename if known
        row = query_db("SELECT filename FROM files WHERE sha256 = ?", (sha256,), one=True)
        as_name = row["filename"] if row else sha256
        return send_from_directory(UPLOAD_DIR, sha256, as_attachment=True, download_name=as_name)

    @app.route("/rules")
    def rules_info():
        if app.yara_rules is None:
            compiled = []
        else:
            try:
                compiled = app.yara_rules.names()  # type: ignore[attr-defined]
            except Exception:
                compiled = []
        rule_files = []
        for root, _, files in os.walk(RULES_DIR):
            for f in files:
                if f.endswith((".yar", ".yara")):
                    rule_files.append(os.path.relpath(os.path.join(root, f), RULES_DIR))
        return render_template("rules.html", compiled_namespaces=compiled, rule_files=sorted(rule_files))

    @app.route("/reload_rules", methods=["POST"])
    def reload_rules():
        app.yara_rules = compile_yara_rules()
        if app.yara_rules is None:
            flash("No YARA rules compiled. Ensure .yar/.yara files exist under rules/.", "warning")
        else:
            flash("YARA rules reloaded successfully.", "success")
        return redirect(request.referrer or url_for("index"))

    return app


# ---------- Helpers ----------

def init_db():
    """Initialize SQLite with required tables."""
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                sha256 TEXT NOT NULL UNIQUE,
                size INTEGER NOT NULL,
                mimetype TEXT NOT NULL,
                uploaded_at TEXT NOT NULL,
                stored_path TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS matches (
                file_id INTEGER NOT NULL,
                rule TEXT NOT NULL,
                FOREIGN KEY (file_id) REFERENCES files(id)
            )
        """)
        conn.commit()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def query_db(query: str, args: Tuple = (), one: bool = False):
    with get_db() as conn:
        cur = conn.execute(query, args)
        rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows


def execute_db(query: str, args: Tuple = ()):
    with get_db() as conn:
        conn.execute(query, args)
        conn.commit()


def sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def compile_yara_rules():
    """Compile all .yar/.yara files under RULES_DIR into a single ruleset with namespaces."""
    if yara is None:
        return None

    filepaths = {}
    for root, _, files in os.walk(RULES_DIR):
        for f in files:
            if f.endswith((".yar", ".yara")):
                full = os.path.join(root, f)
                rel = os.path.relpath(full, RULES_DIR)
                # Use the relative path (sanitized) as the namespace to avoid clashes
                ns = rel.replace(os.sep, "_")
                filepaths[ns] = full

    if not filepaths:
        return None

    try:
        rules = yara.compile(filepaths=filepaths)  # type: ignore[attr-defined]
        return rules
    except Exception as e:
        # You may want to log e or show it in the UI; here we keep it simple
        return None


def run_yara(rules, filepath):
    """Return list of matched rule names for the given file path."""
    try:
        matches = rules.match(str(filepath), timeout=10)  # type: ignore[attr-defined]
        return [m.rule for m in matches]
    except Exception:
        return []


def jaccard_sim(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
