from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
import os, json, sqlite3, hashlib, datetime
from PIL import Image
import pytesseract

# --- Config ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.sqlite3")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}
SECRET_KEY = "dev-secret"  # change for production

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.secret_key = SECRET_KEY

# --- Utils ---
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS students (
            cert_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            roll_no TEXT NOT NULL,
            course TEXT NOT NULL,
            marks TEXT,
            institution TEXT,
            issue_date TEXT,
            hash TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            input_name TEXT, input_roll TEXT, input_course TEXT, input_cert_id TEXT,
            status TEXT NOT NULL, reason TEXT,
            ocr_json TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            cert_id TEXT PRIMARY KEY
        )
    """)
    conn.commit()
    conn.close()

def canonical_string(name, roll, course, cert_id, marks=""):
    return f"Name:{name}|Roll:{roll}|Course:{course}|CertID:{cert_id}|Marks:{marks}".strip()

def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def seed_data():
    conn = get_db()
    cur = conn.cursor()
    # Only seed if empty
    cur.execute("SELECT COUNT(*) as c FROM students")
    if cur.fetchone()["c"] == 0:
        samples = [
            # Valid certificate (use this for success demo)
            dict(cert_id="JH-2023-0001", name="Anika Sharma", roll_no="CSE19001", course="B.Tech CSE",
                 marks="8.6 CGPA", institution="JUT Ranchi", issue_date="2023-06-30"),
            # Another valid certificate
            dict(cert_id="JH-2022-0042", name="Rahul Verma", roll_no="EEE18012", course="B.Tech EEE",
                 marks="7.9 CGPA", institution="NIT Jamshedpur", issue_date="2022-07-15"),
            # Diploma example
            dict(cert_id="JH-2021-0199", name="Priya Singh", roll_no="CIV17007", course="Diploma Civil",
                 marks="81%", institution="Government Polytechnic Ranchi", issue_date="2021-08-20"),
        ]
        for s in samples:
            h = sha256_hex(canonical_string(s["name"], s["roll_no"], s["course"], s["cert_id"], s["marks"]))
            cur.execute("""INSERT INTO students(cert_id, name, roll_no, course, marks, institution, issue_date, hash)
                           VALUES(?,?,?,?,?,?,?,?)""",
                        (s["cert_id"], s["name"], s["roll_no"], s["course"], s["marks"], s["institution"], s["issue_date"], h))
        conn.commit()
    conn.close()

def try_ocr_image(path):
    """Try extracting text using Tesseract. If not available, return empty fields."""
    result = {"raw_text": "", "name": "", "roll_no": "", "course": "", "cert_id": "", "marks": ""}
    try:
        # Attempt OCR
        text = pytesseract.image_to_string(Image.open(path))
        result["raw_text"] = text
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        joined = " ".join(lines).lower()

        # naive pattern guesses
        import re
        # certificate id
        m = re.search(r"(cert(ificate)?\s*id[:#]?\s*|id[:#]?\s*)([a-z0-9\-\/]+)", joined)
        if m: result["cert_id"] = m.group(3).upper()

        # roll number
        m = re.search(r"(roll\s*no[:#]?\s*)([a-z0-9\-\/]+)", joined)
        if m: result["roll_no"] = m.group(2).upper()

        # name
        m = re.search(r"(name[:#]?\s*)([a-z.\s]+)", joined)
        if m:
            n = m.group(2).strip().title()
            result["name"] = " ".join([w for w in n.split() if len(w) > 1])[:60]

        # course
        for kw in ["b.tech cse", "btech cse", "b. tech cse", "b.tech eee", "diploma civil", "bsc", "msc", "mba"]:
            if kw in joined:
                result["course"] = kw.upper()
                break

        # marks
        m = re.search(r"(\b\d{1,2}\.\d\b\s*cgpa|\b\d{2,3}%\b)", joined)
        if m: result["marks"] = m.group(1).upper()

    except Exception as e:
        # If OCR not available or fails, don’t crash the server
        result["raw_text"] = f"[OCR unavailable: {e}]"
    return result

def verify_logic(input_fields, ocr_fields):
    """Core matching rules. Returns (status, reason)."""
    conn = get_db()
    cur = conn.cursor()

    # Check blacklist first
    cur.execute("SELECT 1 FROM blacklist WHERE cert_id = ?", (input_fields.get("cert_id",""),))
    if cur.fetchone():
        return "Invalid", "Certificate ID is blacklisted"

    # Lookup by cert_id if available, else by roll+name
    row = None
    if input_fields.get("cert_id"):
        cur.execute("SELECT * FROM students WHERE cert_id = ?", (input_fields["cert_id"],))
        row = cur.fetchone()
    if row is None and input_fields.get("roll_no") and input_fields.get("name"):
        cur.execute("SELECT * FROM students WHERE roll_no = ? AND LOWER(name) = LOWER(?)",
                    (input_fields["roll_no"], input_fields["name"]))
        row = cur.fetchone()

    if row is None:
        return "Invalid", "No matching record found"

    # Compare fields
    mismatches = []
    for key, db_key in [("name","name"), ("roll_no","roll_no"), ("course","course"), ("cert_id","cert_id")]:
        val = input_fields.get(key, "").strip()
        dbval = str(row[db_key]).strip()
        if val and dbval and val.lower() != dbval.lower():
            mismatches.append(f"{key} mismatch")

    # Hash validation (simulated blockchain)
    calc_hash = sha256_hex(canonical_string(row["name"], row["roll_no"], row["course"], row["cert_id"], row["marks"]))
    if calc_hash != row["hash"]:
        mismatches.append("hash integrity failed")

    if mismatches:
        return "Suspect", ", ".join(mismatches)
    else:
        return "Valid", "All core fields match"

def store_verification(input_fields, status, reason, ocr_json):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""INSERT INTO verifications(ts, input_name, input_roll, input_course, input_cert_id, status, reason, ocr_json)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (datetime.datetime.now().isoformat(timespec="seconds"),
                 input_fields.get("name"), input_fields.get("roll_no"), input_fields.get("course"),
                 input_fields.get("cert_id"), status, reason, json.dumps(ocr_json)[:8000]))
    conn.commit()
    conn.close()

# --- Routes ---
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        roll_no = request.form.get("roll_no","").strip().upper()
        course = request.form.get("course","").strip()
        cert_id = request.form.get("cert_id","").strip().upper()
        file = request.files.get("file")
        extracted = {}

        saved_path = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            saved_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(saved_path)
            extracted = try_ocr_image(saved_path)

            # If OCR fields are empty, try to infer from filename chunks
            if not any([extracted.get("name"), extracted.get("roll_no"), extracted.get("cert_id")]):
                base = os.path.splitext(filename)[0]
                parts = base.replace("-", " ").replace("_", " ").split()
                for p in parts:
                    if p.upper().startswith("JH-"):
                        extracted["cert_id"] = p.upper()

        # Merge user input with OCR, preferring typed inputs
        input_fields = {
            "name": name or extracted.get("name",""),
            "roll_no": roll_no or extracted.get("roll_no",""),
            "course": course or extracted.get("course",""),
            "cert_id": cert_id or extracted.get("cert_id","")
        }

        status, reason = verify_logic(input_fields, extracted)
        store_verification(input_fields, status, reason, extracted)

        flash(f"Status: {status} - {reason}", "success" if status=="Valid" else ("warning" if status=="Suspect" else "danger"))
        return render_template("result.html", status=status, reason=reason, input_fields=input_fields, extracted=extracted, image_path=os.path.basename(saved_path) if saved_path else None)

    return render_template("verify.html")

# --- Admin ---
ADMIN_USER = "admin"
ADMIN_PASS = "admin123"

@app.route("/admin/login", methods=["GET","POST"])
def admin_login():
    if request.method == "POST":
        u = request.form.get("username")
        p = request.form.get("password")
        if u == ADMIN_USER and p == ADMIN_PASS:
            session["admin"] = True
            return redirect(url_for("admin_dashboard"))
        flash("Invalid credentials", "danger")
    return render_template("admin_login.html")

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("index"))

@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM verifications ORDER BY id DESC LIMIT 100")
    rows = cur.fetchall()
    cur.execute("SELECT cert_id FROM blacklist ORDER BY cert_id")
    bl = [r["cert_id"] for r in cur.fetchall()]
    conn.close()
    return render_template("admin_dashboard.html", rows=rows, blacklist=bl)

@app.route("/admin/blacklist", methods=["POST"])
def admin_blacklist():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    cert_id = request.form.get("cert_id","").strip().upper()
    if cert_id:
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute("INSERT OR IGNORE INTO blacklist(cert_id) VALUES(?)", (cert_id,))
            conn.commit()
            flash(f"Blacklisted {cert_id}", "warning")
        finally:
            conn.close()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/unblacklist", methods=["POST"])
def admin_unblacklist():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    cert_id = request.form.get("cert_id","").strip().upper()
    if cert_id:
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute("DELETE FROM blacklist WHERE cert_id = ?", (cert_id,))
            conn.commit()
            flash(f"Removed {cert_id} from blacklist", "success")
        finally:
            conn.close()
    return redirect(url_for("admin_dashboard"))

# --- Startup ---
if __name__ == "__main__":
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    init_db()
    seed_data()
    app.run(host="0.0.0.0", port=5000, debug=True)

from flask import send_from_directory

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
