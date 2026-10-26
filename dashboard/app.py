from flask import Flask, render_template_string, abort, request, redirect, url_for, send_file, session
import os
import secrets
import sqlite3
import uuid
from pathlib import Path
from werkzeug.utils import secure_filename
from collections import Counter
import json
import hashlib
import yaml
import re
import html
import shutil
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.urandom(32)  # Session/CSRF key; refreshed on restart
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB upload limit
ROOT = Path(__file__).resolve().parent.parent

# SCAN_HISTORY_STORAGE_V1
# Private storage for locally-run dashboard scans.
SCAN_STORAGE = ROOT / "data" / "private_scans"
SCAN_DB = SCAN_STORAGE / "scan_history.sqlite3"
SCAN_RETENTION_DAYS = 30


def init_scan_storage():
    SCAN_STORAGE.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(SCAN_STORAGE, 0o700)
    except OSError:
        pass

    with sqlite3.connect(SCAN_DB) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                original_name TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                file_type TEXT NOT NULL,
                score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                message TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                stored_file TEXT NOT NULL,
                stored_report TEXT NOT NULL
            )
        """)
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_created "
            "ON scan_history(created_at)"
        )

    try:
        os.chmod(SCAN_DB, 0o600)
    except OSError:
        pass


def cleanup_old_scans():
    init_scan_storage()
    cutoff = (datetime.now() - timedelta(days=SCAN_RETENTION_DAYS)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with sqlite3.connect(SCAN_DB) as db:
        db.row_factory = sqlite3.Row
        old_rows = db.execute(
            "SELECT id, stored_file, stored_report FROM scan_history "
            "WHERE created_at < ?",
            (cutoff,)
        ).fetchall()

        for row in old_rows:
            for name in (row["stored_file"], row["stored_report"]):
                # Only delete files with our generated UUID filenames.
                if re.fullmatch(r"[0-9a-f]{32}\.(?:bin|json)", name or ""):
                    target = SCAN_STORAGE / name
                    try:
                        target.unlink(missing_ok=True)
                    except OSError:
                        # Keep the database row if cleanup is incomplete.
                        break
            else:
                db.execute("DELETE FROM scan_history WHERE id = ?", (row["id"],))


def load_scan_history():
    cleanup_old_scans()
    with sqlite3.connect(SCAN_DB) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute("""
            SELECT id, created_at, original_name, sha256, file_size,
                   file_type, score, verdict
            FROM scan_history
            ORDER BY id DESC
            LIMIT 50
        """).fetchall()
        return [dict(row) for row in rows]


def save_scan_record(payload, analysis):
    cleanup_old_scans()
    scan_id = uuid.uuid4().hex
    file_name = scan_id + ".bin"
    report_name = scan_id + ".json"
    file_path = SCAN_STORAGE / file_name
    report_path = SCAN_STORAGE / report_name
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = {
        "created_at": created_at,
        "analysis": analysis,
        "retention_days": SCAN_RETENTION_DAYS,
    }

    try:
        # Exclusive creation prevents overwriting an existing file.
        with file_path.open("xb") as f:
            f.write(payload)
        os.chmod(file_path, 0o600)

        with report_path.open("x", encoding="utf-8") as f:
            import json as _json
            _json.dump(report, f, ensure_ascii=False, indent=2)
        os.chmod(report_path, 0o600)

        with sqlite3.connect(SCAN_DB) as db:
            db.execute("""
                INSERT INTO scan_history (
                    created_at, original_name, sha256, file_size,
                    file_type, score, verdict, message, findings_json,
                    stored_file, stored_report
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                created_at, analysis["filename"], analysis["sha256"],
                analysis["size"], analysis["file_type"], analysis["score"],
                analysis["verdict"], analysis["message"],
                _json.dumps(analysis["findings"], ensure_ascii=False),
                file_name, report_name
            ))
    except Exception:
        for target in (file_path, report_path):
            try:
                target.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def require_local_scan_access():
    # These endpoints must remain local-only.
    if request.remote_addr not in {"127.0.0.1", "::1"}:
        abort(403)


def read_rule(path):
    text = path.read_text(errors="replace")
    def field(name, default="Unknown"):
        match = re.search(
            rf"(?m)^{re.escape(name)}:\s*[\"']?([^\"'\n#]+)",
            text
        )
        return match.group(1).strip() if match else default

    return {
        "file": path.name,
        "title": field("title", path.stem.replace("_", " ").title()),
        "level": field("level", "unknown").lower(),
        "status": field("status", "unknown"),
        "id": field("id", ""),
    }

def load_dashboard_data():
    rule_files = sorted((ROOT / "rules").glob("*.yml"))
    rules = [read_rule(p) for p in rule_files]
    severity = Counter(r["level"] for r in rules)

    coverage_path = ROOT / "reports" / "coverage_matrix.json"
    coverage = {"techniques_assessed": 0, "covered": 0,
                "partially_covered": 0, "not_covered": 0}
    techniques = []
    correlations = []

    if coverage_path.exists():
        try:
            data = json.loads(coverage_path.read_text())
            coverage.update(data.get("summary", {}))
            techniques = data.get("techniques", [])
            correlations = data.get("correlations", [])
        except (json.JSONDecodeError, OSError):
            pass

    hunts = sorted((ROOT / "hunts").glob("*.md"))
    incidents = sorted((ROOT / "incidents").glob("*.md"))

    technique_by_rule = {}
    for item in techniques:
        rule_name = item.get("sigma_rule")
        if rule_name:
            technique_by_rule[rule_name] = item.get("technique_id", "—")

    for rule in rules:
        rule["technique"] = technique_by_rule.get(rule["file"], "—")

    severity_order = {"critical": 0, "high": 1, "medium": 2,
                      "low": 3, "informational": 4, "info": 4}
    rules.sort(key=lambda r: (severity_order.get(r["level"], 5),
                             r["title"].lower()))

    return {
        "rules": rules,
        "rule_count": len(rules),
        "severity": severity,
        "coverage": coverage,
        "techniques": techniques,
        "correlations": correlations,
        "hunts": hunts,
        "incidents": incidents,
    }

PAGE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cyberion Defense Labs | Detection Dashboard</title>
<style>
:root{color-scheme:dark;--bg:#0b1120;--panel:#121c2e;--line:#26354b;
--text:#e5edf8;--muted:#9aaac0;--blue:#60a5fa;--green:#34d399}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5
Inter,ui-sans-serif,system-ui,Arial,sans-serif}
header{padding:26px clamp(18px,4vw,48px);background:#101a2b;
border-bottom:1px solid var(--line)}
h1{font-size:clamp(23px,3vw,32px);margin:0}
header p{color:var(--muted);margin:6px 0 0}
main{max-width:1440px;margin:auto;padding:28px clamp(16px,4vw,42px) 48px}
h2{font-size:18px;margin:0 0 16px}
h3{font-size:15px;margin:0 0 8px}
.muted{color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:14px}
.card,.panel{background:var(--panel);border:1px solid var(--line);
border-radius:13px;padding:19px}
.label{font-size:13px;color:var(--muted)}
.number{font-size:32px;font-weight:750;margin-top:5px}
.section{margin-top:25px}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,360px),1fr));gap:16px}
.track{height:10px;background:#26354b;border-radius:99px;overflow:hidden;margin:14px 0}
.fill{height:100%;background:var(--green)}
.coverage-line{display:flex;justify-content:space-between;gap:12px;margin:9px 0}
.pill{display:inline-block;border-radius:99px;padding:3px 9px;font-size:12px;
background:#243449;color:#dbeafe}
.high{color:#fca5a5}.medium{color:#fcd34d}.low{color:#93c5fd}
.unknown{color:var(--muted)}
.tablewrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:560px}
th,td{text-align:left;padding:11px 12px;border-bottom:1px solid var(--line)}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
ul.files{list-style:none;padding:0;margin:0}
.files li{padding:10px 0;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
.files li:last-child{border-bottom:0}
footer{margin-top:30px;color:var(--muted);font-size:12px}
/* IMPORT_RESULT_PANEL_V3 */
.notice{border:1px solid #38bdf8;border-left:5px solid #38bdf8;padding:14px 16px;background:#10243a;color:#f0f9ff;margin:18px 0;border-radius:9px;font-weight:600;overflow-wrap:anywhere}
.notice[role='status']{scroll-margin-top:20px}
.notice strong{display:block;margin-bottom:6px;color:#7dd3fc}
.notice.success{border-color:#22c55e;border-left-color:#22c55e;background:#10291f;color:#dcfce7}
.notice.success strong{color:#86efac}
.notice.error{border-color:#ef4444;border-left-color:#ef4444;background:#301719;color:#fee2e2}
.notice.error strong{color:#fca5a5}
@media(max-width:560px){.number{font-size:27px}.card,.panel{padding:15px}}

/* LIVE_GRAPH_STYLES */
.graph-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr));gap:16px}
.graph-panel{background:var(--panel);border:1px solid var(--line);border-radius:13px;padding:19px;min-width:0}
.graph-subtitle{color:var(--muted);font-size:12px;margin:-8px 0 18px}
.bar-row{display:grid;grid-template-columns:92px minmax(40px,1fr) 30px;align-items:center;gap:10px;margin:14px 0}
.bar-label{font-size:13px;color:var(--muted)}
.bar-track{height:12px;border-radius:99px;background:#26354b;overflow:hidden}
.bar-fill{height:100%;border-radius:99px}
.bar-value{text-align:right;font-weight:700}
.donut-wrap{display:flex;align-items:center;justify-content:center;gap:22px;flex-wrap:wrap;padding:6px 0 12px}
.donut{width:150px;height:150px;border-radius:50%;display:grid;place-items:center;position:relative;flex:0 0 auto}
.donut:before{content:"";position:absolute;width:94px;height:94px;border-radius:50%;background:var(--panel)}
.donut-center{position:relative;text-align:center;z-index:1}
.donut-total{font-size:25px;font-weight:800}
.donut-caption{font-size:11px;color:var(--muted)}
.legend{display:grid;gap:12px}
.legend-item{display:flex;align-items:center;gap:8px;font-size:13px}
.legend-dot{width:10px;height:10px;border-radius:3px;flex:0 0 auto}
.overview-stat{display:flex;justify-content:space-between;gap:12px;margin:12px 0 6px;font-size:13px}
.overview-track{height:9px;border-radius:99px;background:#26354b;overflow:hidden}
.overview-fill{height:100%;border-radius:99px}
@media(max-width:560px){.graph-panel{padding:15px}.bar-row{grid-template-columns:82px minmax(30px,1fr) 25px;gap:7px}}

</style>
</head>
<body>
<header>
  <h1>🛡️ Cyberion Defense Labs</h1>
  <p>Detection Engineering &amp; Threat Hunting Dashboard</p>
</header>
<main>
  <section class="section panel" id="import-data">
    <h2>＋ Import Data</h2>
    <p class="muted">Import validated Sigma rules, a MITRE coverage matrix, or Markdown hunt and incident reports. Maximum file size: 2 MB.</p>
    {% if request.args.get('import_message') %}
      <div class="notice {{ 'success' if request.args.get('import_message', '').startswith(('Import successful:', 'Coverage matrix imported.')) else 'error' }}" role="status" id="import-result" tabindex="-1">
        <strong>{{ '✓ Import Successful' if request.args.get('import_message', '').startswith(('Import successful:', 'Coverage matrix imported.')) else '⚠ Import Needs Attention' }}</strong>
        <div>{{ request.args.get('import_message') }}</div>
      </div>
    {% endif %}
    <form action="/import" method="post" enctype="multipart/form-data"
          style="display:flex;flex-wrap:wrap;gap:12px;align-items:end">
      <div style="flex:1;min-width:190px">
        <label for="import-kind" class="label">Data type</label>
        <select id="import-kind" name="kind" required
                style="display:block;width:100%;margin-top:7px;padding:11px;background:#0a1424;color:#edf4ff;border:1px solid #29415e;border-radius:8px">
          <option value="rules">Sigma Rule (.yml / .yaml)</option>
          <option value="coverage">MITRE Coverage Matrix (.json)</option>
          <option value="hunts">Threat Hunt Report (.md)</option>
          <option value="incidents">Incident Report (.md)</option>
        </select>
      </div>
      <div style="flex:1;min-width:190px">
        <label for="import-file" class="label">Choose file</label>
        <input id="import-file" type="file" name="file" required
               accept=".yml,.yaml,.json,.md"
               style="display:block;width:100%;margin-top:7px;padding:8px;background:#0a1424;color:#edf4ff;border:1px solid #29415e;border-radius:8px">
      </div>
      <button type="submit"
              style="padding:12px 19px;background:linear-gradient(100deg,#1687d9,#087e91);color:white;border:0;border-radius:8px;font-weight:750;cursor:pointer">
        Upload &amp; Validate
      </button>
      <label style="display:flex;gap:8px;align-items:center;width:100%;color:#f8c766;font-size:12px">
        <input type="checkbox" name="replace_coverage" value="yes">
        Replace existing coverage_matrix.json (creates a backup; only applies to coverage imports)
      </label>
    </form>
  </section>


  <!-- FILE_THREAT_ANALYZER_V1 -->
  <section class="section panel" id="file-threat-analyzer">
    <h2>🔎 File Threat Analyzer</h2>
    <p class="muted">Static analysis only. Maximum upload size: 2 MB. Files are never executed. After analysis, the original upload and JSON report are saved locally for scan history and retained for up to 30 days. Delete them using the Scan History actions.</p>
    <form action="/analyze" method="post" enctype="multipart/form-data"
          style="display:flex;flex-wrap:wrap;gap:12px;align-items:end">
      <div style="flex:1;min-width:220px">
        <label for="analyze-file" class="label">Choose a file to inspect</label>
        <input id="analyze-file" type="file" name="file" required
               style="display:block;width:100%;margin-top:7px;padding:8px;background:#0a1424;color:#edf4ff;border:1px solid #29415e;border-radius:8px">
      </div>
      <button type="submit"
              style="padding:12px 19px;background:linear-gradient(100deg,#1687d9,#087e91);color:white;border:0;border-radius:8px;font-weight:750;cursor:pointer">
        Analyze File
      </button>
    </form>
    {% if analysis %}
      <div class="notice {{ 'error' if analysis.error else 'success' }}" role="status" style="margin-top:18px">
        <strong>{{ analysis.verdict }}</strong>
        <div>{{ analysis.message }}</div>
      </div>
      {% if not analysis.error %}
        <p><b>Filename:</b> {{ analysis.filename }}</p>
        <p><b>Detected type:</b> {{ analysis.file_type }}</p>
        <p><b>Size:</b> {{ analysis.size }} bytes</p>
        <p style="overflow-wrap:anywhere"><b>SHA-256:</b> <code>{{ analysis.sha256 }}</code></p>
        <p><b>Heuristic risk score:</b> {{ analysis.score }}/100</p>
        <h3>Findings</h3>
        <ul>
          {% for finding in analysis.findings %}
            <li>{{ finding }}</li>
          {% endfor %}
        </ul>
      {% endif %}
    {% endif %}
  </section>

  <!-- SCAN_HISTORY_PANEL_V1 -->
  <section class="section panel" id="scan-history">
    <h2>🗂️ Scan History</h2>
    <p class="muted">Latest 50 scans. Records and saved files are retained for up to 30 days.</p>
    {% if scan_history %}
      <form method="post" action="{{ url_for('delete_all_scan_history') }}"
            onsubmit="return confirm('Delete ALL saved scans, original files and reports? This cannot be undone.');"
            style="margin:12px 0">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <button type="submit" style="background:#991b1b;color:white;padding:9px 14px;border:0;border-radius:8px;cursor:pointer">
          Delete All Scan History
        </button>
      </form>
      <div style="overflow-x:auto">
        <table>
          <thead><tr>
            <th>Date</th><th>Filename</th><th>Score</th>
            <th>Verdict</th><th>SHA-256</th><th>Saved artifacts</th><th>Actions</th>
          </tr></thead>
          <tbody>
          {% for scan in scan_history %}
            <tr>
              <td>{{ scan.created_at }}</td>
              <td style="overflow-wrap:anywhere">{{ scan.original_name }}</td>
              <td>{{ scan.score }}/100</td>
              <td>{{ scan.verdict }}</td>
              <td><code>{{ scan.sha256 }}</code></td>
              <td>
                <a href="{{ url_for('download_scan_artifact', scan_id=scan.id, kind='report') }}">Report JSON</a>
                ·
                <a href="{{ url_for('download_scan_artifact', scan_id=scan.id, kind='file') }}">Original file</a>
              </td>
              <td>
                <form method="post" action="{{ url_for('delete_scan_history', scan_id=scan.id) }}"
                      onsubmit="return confirm('Delete this scan, its original file and report? This cannot be undone.');">
                  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                  <button type="submit" style="background:#991b1b;color:white;padding:7px 10px;border:0;border-radius:7px;cursor:pointer">
                    Delete
                  </button>
                </form>
              </td>
            </tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    {% else %}
      <p class="muted">No saved scans yet. Analyze a file to create the first history entry.</p>
    {% endif %}
  </section>

  <div class="cards">
    <div class="card"><div class="label">Sigma Rule Files</div><div class="number">{{ d.rule_count }}</div></div>
    <div class="card"><div class="label">ATT&amp;CK Techniques Assessed</div><div class="number">{{ d.coverage.techniques_assessed }}</div></div>
    <div class="card"><div class="label">Threat Hunt Reports</div><div class="number">{{ d.hunts|length }}</div></div>
    <div class="card"><div class="label">Investigation Case Reports</div><div class="number">{{ d.incidents|length }}</div></div>
  </div>


  <!-- LIVE_GRAPHS_SECTION -->
  <section class="section graph-grid" aria-label="Security analytics graphs">
    <div class="graph-panel">
      <h2>📊 Alert Severity Distribution</h2>
      <p class="graph-subtitle">Sigma rules grouped by declared severity</p>
      {% set levels = [('critical','Critical','#ef4444'),('high','High','#f97316'),('medium','Medium','#fbbf24'),('low','Low','#60a5fa'),('informational','Informational','#a78bfa')] %}
      {% set max_sev = [d.severity.get('critical',0),d.severity.get('high',0),d.severity.get('medium',0),d.severity.get('low',0),d.severity.get('informational',0)+d.severity.get('info',0)]|max %}
      {% for level,label,color in levels %}
        {% set count = d.severity.get(level,0)+(d.severity.get('info',0) if level == 'informational' else 0) %}
        <div class="bar-row">
          <span class="bar-label">{{ label }}</span>
          <div class="bar-track"><div class="bar-fill" style="width:{{ (100*count/max_sev if max_sev else 0)|round(1) }}%;background:{{ color }}"></div></div>
          <span class="bar-value">{{ count }}</span>
        </div>
      {% endfor %}
      <p class="muted">Rule metadata only; these are not live alert counts.</p>
    </div>

    <div class="graph-panel">
      <h2>🍩 MITRE ATT&amp;CK Coverage</h2>
      <p class="graph-subtitle">Status of assessed techniques</p>
      {% set total = d.coverage.techniques_assessed|int %}
      {% set covered = d.coverage.covered|int %}
      {% set partial = d.coverage.partially_covered|int %}
      {% set uncovered = d.coverage.not_covered|int %}
      {% set cp = (100*covered/total if total else 0)|round(1) %}
      {% set pp = (100*partial/total if total else 0)|round(1) %}
      {% set edge = cp+pp %}
      <div class="donut-wrap">
        <div class="donut" role="img" aria-label="{{ covered }} covered, {{ partial }} partial, {{ uncovered }} not covered" style="background:conic-gradient(#34d399 0% {{ cp }}%,#fbbf24 {{ cp }}% {{ edge }}%,#64748b {{ edge }}% 100%)">
          <div class="donut-center"><div class="donut-total">{{ total }}</div><div class="donut-caption">techniques</div></div>
        </div>
        <div class="legend">
          <div class="legend-item"><span class="legend-dot" style="background:#34d399"></span>Covered <strong>{{ covered }}</strong></div>
          <div class="legend-item"><span class="legend-dot" style="background:#fbbf24"></span>Partially covered <strong>{{ partial }}</strong></div>
          <div class="legend-item"><span class="legend-dot" style="background:#64748b"></span>Not covered <strong>{{ uncovered }}</strong></div>
        </div>
      </div>
      <p class="muted">Source: reports/coverage_matrix.json</p>
    </div>

    <div class="graph-panel">
      <h2>📈 Project Overview</h2>
      <p class="graph-subtitle">Current project resource counts</p>
      {% set items = [('Sigma rules',d.rule_count,'#60a5fa'),('Threat hunt reports',d.hunts|length,'#34d399'),('Incident reports',d.incidents|length,'#fbbf24')] %}
      {% set biggest = [d.rule_count,d.hunts|length,d.incidents|length]|max %}
      {% for label,count,color in items %}
        <div class="overview-stat"><span>{{ label }}</span><strong>{{ count }}</strong></div>
        <div class="overview-track"><div class="overview-fill" style="width:{{ (100*count/biggest if biggest else 0)|round(1) }}%;background:{{ color }}"></div></div>
      {% endfor %}
      <p class="muted">Counts are read from the local project folders.</p>
    </div>
  </section>

  <div class="section grid2">
    <section class="panel">
      <h2>MITRE ATT&amp;CK Coverage</h2>
      <div class="coverage-line"><span>Covered</span><strong>{{ d.coverage.covered }}</strong></div>
      <div class="coverage-line"><span>Partially covered</span><strong>{{ d.coverage.partially_covered }}</strong></div>
      <div class="coverage-line"><span>Not covered</span><strong>{{ d.coverage.not_covered }}</strong></div>
      {% set total = d.coverage.techniques_assessed|int %}
      <div class="track"><div class="fill" style="width:{{ (100*d.coverage.covered/total if total else 0)|round(1) }}%"></div></div>
      <p class="muted">{{ d.coverage.covered }} of {{ total }} assessed techniques marked covered
      ({{ (100*d.coverage.covered/total if total else 0)|round(1) }}%).</p>
      <a href="/report/reports/coverage_matrix.md">Read coverage matrix →</a>
    </section>
    <section class="panel">
      <h2>Sigma Rule Severity</h2>
      {% for level, label, css in [('critical','Critical','high'),('high','High','high'),('medium','Medium','medium'),('low','Low','low'),('informational','Informational','unknown')] %}
      <div class="coverage-line"><span class="{{ css }}">{{ label }}</span><strong>{{ d.severity.get(level, 0) }}</strong></div>
      {% endfor %}
      <p class="muted">Counts are read from each YAML rule's <code>level</code> field.</p>
    </section>
  </div>

  <section class="section panel">
    <h2>Sigma Detection Rules</h2>
    <p class="muted">Rule metadata loaded from the local rules directory. Severity is rule metadata, not proof of a live attack.</p>
    <div class="tablewrap"><table>
      <thead><tr><th>Rule</th><th>ATT&amp;CK ID</th><th>Level</th><th>Status</th></tr></thead>
      <tbody>
      {% for r in d.rules %}
      <tr><td>{{ r.title }}</td><td>{{ r.technique }}</td>
      <td class="{{ r.level if r.level in ['high','medium','low'] else 'unknown' }}">{{ r.level|title }}</td>
      <td>{{ r.status }}</td></tr>
      {% else %}<tr><td colspan="4">No Sigma YAML files found.</td></tr>{% endfor %}
      </tbody>
    </table></div>
  </section>

  <div class="section grid2">
    <section class="panel">
      <h2>Threat Hunting</h2>
      <ul class="files">
      {% for f in d.hunts %}
        <li><a href="/report/hunts/{{ f.name }}">{{ f.stem.replace('_',' ') }}</a></li>
      {% else %}<li class="muted">No hunt reports found.</li>{% endfor %}
      </ul>
      <p class="muted">Hunt matches are investigative leads and do not automatically confirm malicious activity.</p>
    </section>
    <section class="panel">
      <h2>Incident Investigation</h2>
      <ul class="files">
      {% for f in d.incidents %}
        <li><a href="/report/incidents/{{ f.name }}">{{ f.stem.replace('_',' ') }}</a></li>
      {% else %}<li class="muted">No incident reports found.</li>{% endfor %}
      </ul>
      <p class="muted">Current case reports describe investigation leads, not confirmed incidents.</p>
    </section>
  </div>

  <section class="section panel">
    <h2>Correlation Evidence Status</h2>
    {% for c in d.correlations %}
    <div style="padding:10px 0;border-bottom:1px solid var(--line)">
      <strong>{{ c.name }}</strong><br>
      <span class="pill">{{ c.status }}</span>
      <p class="muted">{{ c.evidence }}</p>
    </div>
    {% else %}<p class="muted">No correlation records found in coverage JSON.</p>{% endfor %}
  </section>

  <div class="notice">Local project dashboard. Values are loaded from files on disk when the page is requested. This is not a live endpoint-monitoring system; it displays the project's documented artifacts and rule metadata.</div>
  <footer>Cyberion Defense Labs · Local development view · Refresh the page to reload project files</footer>
</main>
</body>
</html>
"""

@app.context_processor
def inject_scan_history():
    try:
        history = load_scan_history()
    except (OSError, sqlite3.Error):
        app.logger.exception("Could not load scan history")
        history = []

    csrf_token = session.setdefault("csrf_token", uuid.uuid4().hex)
    return {"scan_history": history, "csrf_token": csrf_token}


@app.route("/")
def dashboard():
    return render_template_string(PAGE, d=load_dashboard_data())


@app.route("/import", methods=["POST"])
def import_data():
    kind = request.form.get("kind", "")
    uploaded = request.files.get("file")
    replace_coverage = request.form.get("replace_coverage") == "yes"

    def result(message):
        return redirect(url_for("dashboard", import_message=message))

    folders = {
        "rules": ROOT / "rules",
        "hunts": ROOT / "hunts",
        "incidents": ROOT / "incidents",
    }

    if kind not in {"rules", "coverage", "hunts", "incidents"}:
        return result("Import rejected: choose a supported data type.")
    if uploaded is None or not uploaded.filename:
        return result("Import rejected: choose a file first.")

    filename = secure_filename(uploaded.filename)
    if not filename:
        return result("Import rejected: invalid filename.")

    payload = uploaded.read(2 * 1024 * 1024 + 1)
    if not payload or len(payload) > 2 * 1024 * 1024:
        return result("Import rejected: file is empty or exceeds the 2 MB limit.")

    try:
        if kind == "rules":
            if Path(filename).suffix.lower() not in {".yml", ".yaml"}:
                return result("Import rejected: Sigma rules must use .yml or .yaml.")
            document = yaml.safe_load(payload.decode("utf-8"))
            if not isinstance(document, dict) or not all(
                key in document for key in ("title", "logsource", "detection")
            ):
                return result("Import rejected: YAML must contain title, logsource and detection fields.")
            if not isinstance(document["logsource"], dict) or not isinstance(document["detection"], dict):
                return result("Import rejected: logsource and detection must be YAML mappings.")
            level = str(document.get("level", "unknown")).lower()
            if level not in {"critical", "high", "medium", "low", "informational", "info", "unknown"}:
                return result("Import rejected: unsupported Sigma severity level.")
            target = folders["rules"] / filename

        elif kind == "coverage":
            if Path(filename).suffix.lower() != ".json":
                return result("Import rejected: coverage matrix must be a .json file.")
            document = json.loads(payload.decode("utf-8"))
            summary = document.get("summary") if isinstance(document, dict) else None
            techniques = document.get("techniques") if isinstance(document, dict) else None
            if not isinstance(summary, dict) or not isinstance(techniques, list):
                return result("Import rejected: JSON must contain summary and techniques.")
            required = {"techniques_assessed", "covered", "partially_covered", "not_covered"}
            if not required.issubset(summary):
                return result("Import rejected: coverage summary is missing required counts.")
            if not all(isinstance(summary[k], int) and summary[k] >= 0 for k in required):
                return result("Import rejected: coverage counts must be non-negative integers.")
            if summary["techniques_assessed"] != len(techniques):
                return result("Import rejected: assessed count must match the techniques list.")
            if not all(isinstance(item, dict) for item in techniques):
                return result("Import rejected: each technique must be a JSON object.")

            target = ROOT / "reports" / "coverage_matrix.json"
            if target.exists() and not replace_coverage:
                return result("Coverage matrix already exists. Tick the replace confirmation to replace it; a backup will be created.")

        else:
            if Path(filename).suffix.lower() != ".md":
                return result("Import rejected: reports must use .md.")
            if not payload.decode("utf-8").strip():
                return result("Import rejected: Markdown report is empty.")
            target = folders[kind] / filename

    except (UnicodeDecodeError, yaml.YAMLError, json.JSONDecodeError, AttributeError, TypeError, ValueError) as exc:
        return result("Import rejected: file content is invalid (" + type(exc).__name__ + ").")

    target.parent.mkdir(parents=True, exist_ok=True)

    if kind == "coverage" and target.exists():
        backup_name = target.with_name(
            target.name + ".backup_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        )
        try:
            shutil.copy2(target, backup_name)
            target.write_bytes(payload)
        except OSError:
            return result("Import failed while saving the coverage matrix. Check filesystem permissions.")
        return result("Coverage matrix imported. Previous version backed up as " + backup_name.name + ".")

    # Never overwrite existing rule or report files.
    try:
        with target.open("xb") as output:
            output.write(payload)
    except FileExistsError:
        return result("Import rejected: a file with that name already exists. Rename your upload and retry.")
    except OSError:
        return result("Import failed while saving the file. Check filesystem permissions.")

    return result("Import successful: " + target.name + ". Dashboard data will reload on refresh.")


@app.route("/analyze", methods=["POST"])
def analyze_file():
    uploaded = request.files.get("file")
    result = {
        "error": True,
        "verdict": "Analysis not completed",
        "message": "Choose a file and try again."
    }

    if not uploaded or not uploaded.filename:
        return render_template_string(
            PAGE, d=load_dashboard_data(), analysis=result
        )

    filename = secure_filename(uploaded.filename) or "uploaded_file"
    payload = uploaded.stream.read(2 * 1024 * 1024 + 1)

    if len(payload) > 2 * 1024 * 1024:
        result["message"] = "File exceeds the 2 MB analysis limit."
        return render_template_string(
            PAGE, d=load_dashboard_data(), analysis=result
        )

    if not payload:
        result["message"] = "The selected file is empty."
        return render_template_string(
            PAGE, d=load_dashboard_data(), analysis=result
        )

    sample = payload[:8192]
    ext = Path(filename).suffix.lower()
    file_type = "Unknown / unrecognized format"

    signatures = [
        (b"MZ", "Windows executable (PE candidate)"),
        (b"\x7fELF", "ELF executable"),
        (b"%PDF-", "PDF document"),
        (b"PK\x03\x04", "ZIP-based archive"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound document"),
        (b"\x89PNG\r\n\x1a\n", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"),
        (b"GIF87a", "GIF image"),
        (b"GIF89a", "GIF image"),
    ]

    for signature, label in signatures:
        if sample.startswith(signature):
            file_type = label
            break
    else:
        if b"\x00" not in sample:
            try:
                sample.decode("utf-8")
                file_type = "Text / UTF-8-compatible content"
            except UnicodeDecodeError:
                file_type = "Text-like or unknown binary content"
        else:
            file_type = "Unknown binary content"

    text_sample = payload[:].decode("utf-8", errors="ignore")
    patterns = [
        (r"powershell(?:\.exe)?\s+.{0,80}-(?:enc|encodedcommand)\b",
         30, "PowerShell encoded-command pattern"),
        (r"\b(?:downloadstring|downloadfile|invoke-webrequest)\b",
         20, "Script contains a download-related command"),
        (r"\b(?:invoke-expression|iex)\s*[\(\s]",
         20, "Dynamic script execution pattern"),
        (r"\b(?:frombase64string|certutil\s+.{0,40}-decode)\b",
         20, "Base64 decoding or certutil decode pattern"),
        (r"\b(?:vssadmin\s+delete\s+shadows|wbadmin\s+delete)\b",
         30, "Command associated with deleting recovery data"),
        (r"\b(?:mimikatz|sekurlsa::|lsadump::)\b",
         35, "Credential-theft tool or command indicator"),
        (r"\b(?:createremotethread|virtualallocex|writeprocessmemory)\b",
         25, "Process-injection API indicator"),
        (r"\b(?:schtasks|reg\s+add)\b.{0,100}\b(?:run|currentversion\\run)\b",
         15, "Possible persistence-related command pattern"),
    ]

    score = 0
    findings = []

    for pattern, points, description in patterns:
        if re.search(pattern, text_sample, flags=re.IGNORECASE):
            score += points
            findings.append(description)

    executable_exts = {".exe", ".dll", ".scr", ".com", ".msi"}
    script_exts = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".sh", ".py"}

    if file_type in {"Windows executable (PE candidate)", "ELF executable"}:
        score += 20
        findings.append("Executable file signature detected; this alone does not prove malware.")

    if ext in script_exts:
        score += 10
        findings.append("Script file extension: inspect the code before running it.")

    if ext in executable_exts and not (
        file_type == "Windows executable (PE candidate)"
        or file_type == "ELF executable"
    ):
        score += 15
        findings.append("Executable-like extension does not match the detected signature.")

    score = min(score, 100)

    if score >= 50:
        verdict = "HIGH RISK INDICATORS"
        message = "Multiple or strong suspicious indicators matched. Treat this file cautiously."
    elif score >= 20:
        verdict = "SUSPICIOUS — REVIEW REQUIRED"
        message = "One or more risk indicators matched. Review the findings before using the file."
    else:
        verdict = "LOW RISK SCORE — NOT A SAFETY GUARANTEE"
        message = "Few configured indicators matched. This does not prove the file is safe."

    if not findings:
        findings.append("No configured suspicious patterns matched the inspected content.")

    result = {
        "error": False,
        "filename": filename,
        "file_type": file_type,
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "score": score,
        "verdict": verdict,
        "message": message,
        "findings": findings,
    }

    try:
        save_scan_record(payload, result)
    except (OSError, sqlite3.Error, ValueError):
        app.logger.exception("Scan completed but could not be saved to history")
        result["message"] += " Warning: scan completed, but history storage failed."

    return render_template_string(
        PAGE, d=load_dashboard_data(), analysis=result
    )


@app.route("/scan-history/<int:scan_id>/<kind>")
def download_scan_artifact(scan_id, kind):
    require_local_scan_access()
    if kind not in {"file", "report"}:
        abort(404)

    cleanup_old_scans()
    with sqlite3.connect(SCAN_DB) as db:
        db.row_factory = sqlite3.Row
        row = db.execute(
            "SELECT original_name, stored_file, stored_report "
            "FROM scan_history WHERE id = ?",
            (scan_id,)
        ).fetchone()

    if row is None:
        abort(404)

    stored_name = row["stored_file"] if kind == "file" else row["stored_report"]
    if not re.fullmatch(r"[0-9a-f]{32}\.(?:bin|json)", stored_name or ""):
        abort(404)

    target = (SCAN_STORAGE / stored_name).resolve()
    if target.parent != SCAN_STORAGE.resolve() or not target.is_file():
        abort(404)

    if kind == "file":
        return send_file(
            target, as_attachment=True,
            download_name=row["original_name"],
            mimetype="application/octet-stream"
        )

    return send_file(
        target, as_attachment=True,
        download_name=f"scan_report_{scan_id}.json",
        mimetype="application/json"
    )


def validate_stored_scan_name(name):
    if not re.fullmatch(r"[0-9a-f]{32}\.(?:bin|json)", name or ""):
        return None
    target = (SCAN_STORAGE / name).resolve()
    if target.parent != SCAN_STORAGE.resolve():
        return None
    return target


def check_delete_request():
    require_local_scan_access()
    submitted = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    if not expected or not submitted or not secrets.compare_digest(expected, submitted):
        abort(400, description="Invalid or missing CSRF token.")


@app.route("/scan-history/<int:scan_id>/delete", methods=["POST"])
def delete_scan_history(scan_id):
    check_delete_request()

    with sqlite3.connect(SCAN_DB) as db:
        db.row_factory = sqlite3.Row
        row = db.execute(
            "SELECT stored_file, stored_report FROM scan_history WHERE id = ?",
            (scan_id,)
        ).fetchone()

    if row is None:
        abort(404)

    targets = [
        validate_stored_scan_name(row["stored_file"]),
        validate_stored_scan_name(row["stored_report"]),
    ]
    if any(target is None for target in targets):
        abort(404)

    try:
        for target in targets:
            target.unlink(missing_ok=True)

        with sqlite3.connect(SCAN_DB) as db:
            db.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))
    except OSError:
        app.logger.exception("Could not completely delete scan %s", scan_id)
        abort(500, description="Could not delete all scan files. Check server logs and retry.")

    return redirect(url_for("dashboard") + "#scan-history")


@app.route("/scan-history/delete-all", methods=["POST"])
def delete_all_scan_history():
    check_delete_request()

    cleanup_old_scans()
    deleted = 0

    with sqlite3.connect(SCAN_DB) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            "SELECT id, stored_file, stored_report FROM scan_history ORDER BY id"
        ).fetchall()

        for row in rows:
            targets = [
                validate_stored_scan_name(row["stored_file"]),
                validate_stored_scan_name(row["stored_report"]),
            ]
            if any(target is None for target in targets):
                app.logger.error("Skipping scan %s: invalid stored filename", row["id"])
                continue

            try:
                for target in targets:
                    target.unlink(missing_ok=True)
            except OSError:
                app.logger.exception("Could not delete files for scan %s", row["id"])
                continue

            db.execute("DELETE FROM scan_history WHERE id = ?", (row["id"],))
            deleted += 1

    app.logger.info("Delete All Scan History completed: %s records removed", deleted)
    return redirect(url_for("dashboard") + "#scan-history")


@app.route("/health")
def health():
    return {"status": "ok"}

@app.route("/report/<kind>/<path:name>")
def report(kind, name):
    allowed = {"reports", "hunts", "incidents"}
    if kind not in allowed:
        abort(404)
    base = (ROOT / kind).resolve()
    target = (base / name).resolve()
    if base not in target.parents or not target.is_file() or target.suffix.lower() != ".md":
        abort(404)
    content = target.read_text(errors="replace")
    safe = html.escape(content)
    return f"""<!doctype html><html><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{html.escape(target.name)}</title>
    <style>body{{max-width:1000px;margin:30px auto;padding:0 18px;background:#0b1120;color:#e5edf8;font:15px/1.7 Arial}}
    pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#121c2e;border:1px solid #26354b;border-radius:12px;padding:20px}}
    a{{color:#60a5fa}}</style></head><body><p><a href="/">← Back to dashboard</a></p>
    <h2>{html.escape(target.name)}</h2><pre>{safe}</pre></body></html>"""

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
