
# Flask YARA File Scanner

A minimal web app to upload files, scan them against a directory of YARA rules, store metadata in SQLite, and
flag new uploads that are **similar** to previously uploaded files by comparing the overlap of matched YARA rules.

## Features
- Web GUI to upload files
- Scans with YARA (`yara-python`) against all `.yar`/`.yara` files in the `rules/` folder (recursively)
- Stores file metadata (SHA-256, size, MIME) and matched rules in SQLite
- Shows details for each file, including matched rules and **similar files** (based on Jaccard overlap of rule names)
- Button to reload YARA rules without restarting the server

> **Similarity rule**: Two files are considered similar if they share at least one matched YARA rule.
> The UI also displays a Jaccard similarity score = |overlap| / |union| of matched rule sets.

## Quick start
1. **Install dependencies** (create a venv if you like):
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Add/verify YARA rules** in the `rules/` folder. The app ships with `rules/example.yar` as a basic test rule.

3. **Run**:
   ```bash
   export FLASK_APP=app.py
   export FLASK_ENV=development  # optional for auto-reload
   flask run --host 0.0.0.0 --port 5000
   ```

4. Open http://localhost:5000

## Notes
- Uploaded files are stored under `uploads/` using their SHA-256 as filename. If you upload the same content twice, the app de-duplicates and links to the existing record.
- The SQLite database file is created under `instance/scanner.db`.
- To reload YARA rules after adding/changing rule files, click **Reload Rules** in the top navigation.

## Security considerations
- Treat uploaded content as **untrusted**. The app never executes files; it only reads for hashing and scanning.
- Run the service in a sandboxed environment if you expect malicious samples.
- Make sure you **trust your rules**; malformed or heavy rules can cause performance issues.
