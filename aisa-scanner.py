#!/usr/bin/env python3
"""
AISA-Scanner: Autonomous AI Security Agent
Self-training binary risk model + dynamic AI scanning
Haroon Ahmad Awan
"""
import sys, os, re, json, time, random, string, argparse, warnings, asyncio, socket, sqlite3, gzip, io, requests
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import httpx, dns.resolver, torch, joblib, matplotlib.pyplot as plt, base64, html
from transformers import pipeline as hf_pipeline, logging as hf_logging
from sklearn.linear_model import SGDClassifier
import numpy as np

warnings.filterwarnings("ignore", category=DeprecationWarning)
requests.packages.urllib3.disable_warnings()

# ──  CONFIG & TAXONOMY MAPS  ──────────────────────────────────────────────────────────────────────

JSON_DIR = Path(__file__).parent / "taxonomy_maps"
JSON_DIR.mkdir(exist_ok=True)

DEFAULT_MITRE_MAP = {
  "Injection":["T1190","T1059"], "Broken Authentication":["T1078","T1110"],
  "Sensitive Data Exposure":["T1041"], "XML External Entities":["T1220","T1059"],
  "Broken Access Control":["T1068"], "Security Misconfiguration":["T1505"],
  "Cross-Site Scripting":["T1189","T1059"], "Insecure Deserialization":["T1500"],
  "Using Components with Known Vulnerabilities":["T1195"],
  "Insufficient Logging & Monitoring":["T1005"]
}
DEFAULT_CEH_MAP = {
  "Injection":["Module 15 – SQLi"], "Broken Authentication":["Module 14 – Web Apps"],
  "Sensitive Data Exposure":["Module 19 – Cloud"], "XML External Entities":["Module 14 – Web Apps"],
  "Broken Access Control":["Module 14 – Web Apps"], "Security Misconfiguration":["Module 13 – Web Servers"],
  "Cross-Site Scripting":["Module 14 – Web Apps"], "Insecure Deserialization":["Module 14 – Web Apps"],
  "Using Components with Known Vulnerabilities":["Module 05 – Vuln Analysis"],
  "Insufficient Logging & Monitoring":["Module 12 – Evasion"]
}
DEFAULT_SANS_MAP = {
 "CWE-787":"OOB-Write #1","CWE-79":"XSS #2","CWE-89":"SQLi #3",
 "CWE-78":"OS-Cmd-Inj #4","CWE-416":"UAF #5","CWE-20":"Input Valid #6",
 "CWE-125":"OOB-Read #7","CWE-22":"PathTrav #8","CWE-352":"CSRF #9","CWE-434":"FileUpload #10",
 "CWE-190":"IntOverflow #11","CWE-476":"NULL Deref #12","CWE-732":"BadPerms #13",
 "CWE-522":"WeakCreds #14","CWE-611":"XXE #15","CWE-400":"ResExh #16",
 "CWE-94":"CodeInj #17","CWE-306":"MissAuth #18","CWE-269":"PrivMgmt #19",
 "CWE-798":"HardCreds #20","CWE-502":"UnsafeDeser #21","CWE-918":"SSRF #22",
 "CWE-862":"MissAuthZ #23","CWE-522#TLS":"WeakTLS #24","CWE-138":"BadCert #25"
}
MAP_URLS = {
  "owasp_to_mitre.json":"https://raw.githubusercontent.com/emmanuelgjr/owaspllmtop10mapping/main/mappings/owasp_to_mitre.json",
  "label_to_ceh.json":"https://raw.githubusercontent.com/LoGan070raGnaR/CEHGuideBook/main/map/owasp_to_ceh.json",
  "cwe_to_sans.json":"https://raw.githubusercontent.com/gabrielfs7/cwe-top-25/master/top25.json"
}

def _ensure_map(name, default):
    fp = JSON_DIR / name
    if not fp.exists() or fp.stat().st_size < 50:
        try:
            r = requests.get(MAP_URLS[name], timeout=6)
            r.raise_for_status()
            fp.write_bytes(r.content)
        except:
            fp.write_text(json.dumps(default))
    try:
        return json.load(fp.open())
    except:
        return default

MITRE_MAP = {**DEFAULT_MITRE_MAP, **_ensure_map("owasp_to_mitre.json", DEFAULT_MITRE_MAP)}
CEH_MAP   = {**DEFAULT_CEH_MAP,   **_ensure_map("label_to_ceh.json",   DEFAULT_CEH_MAP)}
SANS_MAP  = {**DEFAULT_SANS_MAP,  **_ensure_map("cwe_to_sans.json",    DEFAULT_SANS_MAP)}

def map_labels(labels, mapping):
    out = set()
    for lb in labels:
        v = mapping.get(lb)
        if v: out.update(v if isinstance(v, list) else [v])
    return list(out)

# ──  CVE DETAILS BOOTSTRAP ─────────────────────────────────────────────────────────────────────────

def bootstrap_cve_details_cache(json_dir: Path):
    """
    Download recent NVD feed, extract ID/description/CVSS/CWE → cve_details.json
    """
    print("Bootstrapping CVE details cache…")
    url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"
    r = requests.get(url, timeout=30)
    with gzip.open(io.BytesIO(r.content), mode="rt", encoding="utf-8") as f:
        feed = json.load(f)

    details = {}
    for item in feed["CVE_Items"]:
        cid = item["cve"]["CVE_data_meta"]["ID"]
        desc = item["cve"]["description"]["description_data"][0]["value"]
        impact = item.get("impact", {})
        cv3 = impact.get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore")
        cv2 = impact.get("baseMetricV2", {}).get("cvssV2", {}).get("baseScore")
        score = cv3 if cv3 is not None else (cv2 or 0)
        probs = item["cve"]["problemtype"]["problemtype_data"]
        cwe = ""
        if probs and probs[0]["description"]:
            cwe = probs[0]["description"][0]["value"]
        details[cid] = {"description": desc, "cvss": score, "cwe": cwe}

    fp = json_dir / "cve_details.json"
    fp.write_text(json.dumps(details, indent=2))
    print(f"→ Wrote {len(details)} CVE entries to {fp}")

# ensure we have CVE_DETAILS
det = JSON_DIR/"cve_details.json"
if not det.exists():
    bootstrap_cve_details_cache(JSON_DIR)
CVE_DETAILS = {}
if det.exists():
    try:
        CVE_DETAILS = json.load(det.open())
    except:
        CVE_DETAILS = {}

# ──  CVE & MSF ENRICHMENT (FIXED) ───────────────────────────────────────────────────────────────

# ──  CVE & Metasploit enrichment  ───────────────────────────────────────────────────────────────

MSF_URL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules_metadata_base.json"

def _load_msf():
    cache = JSON_DIR / "modules_metadata.json"

    # Fetch if missing or empty
    if not cache.exists() or cache.stat().st_size < 500:
        try:
            r = requests.get(MSF_URL, timeout=10)
            r.raise_for_status()
            cache.write_bytes(r.content)
        except Exception as e:
            print(f"[!MSF] fetch error: {e}")
            return {}

    try:
        # Load with UTF-8
        raw_text = cache.read_text(encoding="utf-8", errors="replace")
        data = json.loads(raw_text)

        msf_by_cve = defaultdict(list)

        for module, meta in data.items():
            for ref in meta.get("references", []):
                if ref.startswith("CVE-"):
                    msf_by_cve[ref.upper()].append(module)
                elif "CVE-" in ref:
                    # also allow "URL-..." refs
                    match = re.search(r"CVE-\d{4}-\d{4,7}", ref)
                    if match:
                        msf_by_cve[match.group(0).upper()].append(module)

        return msf_by_cve

    except Exception as e:
        print(f"[!MSF] parse error: {e}")
        return {}

MSF_BY_CVE = _load_msf()

def msf_for(cves):
    out = []
    for cid in cves:
        for mod in MSF_BY_CVE.get(cid.upper(), []):
            out.append({"cve": cid, "module": mod})
    return out or ["no metasploit module found"]


def enrich_cve(c):
    """
    Enrich a CVE dictionary with description, CVSS, CWE, and mapped SANS/CEH/MITRE.
    This assumes CVE_DETAILS is already loaded and SecBERT + mapping dictionaries exist.
    """
    cid = c["id"].upper()
    full = CVE_DETAILS.get(cid)
    if not full:
        return c

    # Fill base fields
    c.setdefault("description", full.get("description", ""))
    c.setdefault("cvss", full.get("cvss", 0))
    c.setdefault("cwe", full.get("cwe", ""))

    # SANS from CWE
    if c["cwe"] in SANS_MAP:
        c["sans"] = SANS_MAP[c["cwe"]]

    # MITRE + CEH from description using SecBERT
    desc = c.get("description", "")
    if desc:
        labels = secbert_labels(desc, min_score=0.05)
        owasp = [x["label"] for x in labels]
        c["mitre"] = map_labels(owasp, MITRE_MAP)
        c["ceh"]   = map_labels(owasp, CEH_MAP)

    return c



hf_logging.set_verbosity_error()
try:
    NER = hf_pipeline("ner", "dslim/bert-base-NER", aggregation_strategy="simple",
                      device=0 if torch.cuda.is_available() else -1)
except:
    NER = None

def extract_cves_ner(text):
    if not NER:
        return []
    return list({e["word"].upper()
                 for e in NER(text[:1200]) if e["word"].startswith("CVE-")})

def msf_for(cves):
    return [{"cve":cid, "module":mod}
            for cid in cves for mod in MSF_BY_CVE.get(cid, [])]

# ──  AI LABELING PIPELINES ────────────────────────────────────────────────────────────────────────

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
def _try_pipe(task, model):
    try:
        return hf_pipeline(task, model, device=0 if device.type=="cuda" else -1)
    except:
        return lambda *a,**k: []

SEC_PIPE  = _try_pipe("zero-shot-classification", "jackaduma/SecBERT-distil")
OWASP = ["Injection","Broken Authentication","Sensitive Data Exposure",
         "XML External Entities","Broken Access Control","Security Misconfiguration",
         "Cross-Site Scripting","Insecure Deserialization",
         "Using Components with Known Vulnerabilities","Insufficient Logging & Monitoring"]

def secbert_labels(text, top=3, min_score=0.0):
    res = SEC_PIPE(text, candidate_labels=OWASP)
    items = []
    if isinstance(res, dict):
        for l,s in zip(res.get("labels",[]), res.get("scores",[])):
            items.append({"label":l,"score":round(s,3)})
    elif isinstance(res, list):
        for e in res:
            lbl = e.get("label") or e.get("entity")
            scr = e.get("score", 0)
            if lbl:
                items.append({"label":lbl,"score":round(scr,3)})
    filtered = [it for it in items if it["score"]>=min_score]
    filtered.sort(key=lambda x: x["score"], reverse=True)
    return filtered[:top]

# ──  AUTO-SUBDOMAIN DISCOVERY ─────────────────────────────────────────────────────────────────────

PREFIXES = "www api admin dev stage test beta prod auth pay img static files cdn blog portal vpn git ci cd mail db srv".split()
def enum_subs(domain, numeric_max=15, concurrency=256):
    wild = set()
    try:
        rnd = "".join(random.choice(string.ascii_lowercase) for _ in range(12))
        wild.add(socket.gethostbyname(f"{rnd}.{domain}"))
    except: pass

    cand = set(f"{p}.{domain}" for p in PREFIXES)
    for p in PREFIXES:
        cand.update(f"{p}{i}.{domain}" for i in range(numeric_max))

    live = []
    def try_resolve(fq):
        try:
            dns.resolver.resolve(fq, "A", lifetime=2)
            return True
        except:
            try:
                socket.gethostbyname(fq)
                return True
            except:
                return False

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        for fq, ok in zip(cand, pool.map(try_resolve, cand)):
            if ok:
                ip = ""
                try: ip = socket.gethostbyname(fq)
                except: pass
                if ip not in wild:
                    live.append(fq)
    return live

# ──  HTTP & DB HELPERS ───────────────────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT = httpx.Timeout(6.0, connect=3.0)
async def fetch_get(url, client):
    try:
        r = await client.get(url, follow_redirects=True, timeout=DEFAULT_TIMEOUT)
        return r.status_code, r.text
    except:
        return None, ""

DB_PATH="findings.db"
def db_init():
    with sqlite3.connect(DB_PATH) as c:
        c.execute("""
          CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY,
            ts TEXT,
            data TEXT
          )""")
def db_add(rec):
    with sqlite3.connect(DB_PATH) as c:
        c.execute("INSERT INTO findings(ts,data) VALUES(?,?)",
                  (datetime.now().isoformat(" ","seconds"), json.dumps(rec)))

# ──  RISK MODEL & FEATURES ───────────────────────────────────────────────────────────────────────

FEATURE_KEYS = ["status","banner_len","n_cves","n_msf","n_mitre","n_ceh","secbert_avg"]
class RiskModel:
    def __init__(self, path="scanner_model.pkl"):
        self.path = path; self.first = False
        if os.path.exists(path):
            try:
                self.model = joblib.load(path)
                self.first = True
            except:
                self.model = SGDClassifier(loss="log_loss", max_iter=1000)
        else:
            self.model = SGDClassifier(loss="log_loss", max_iter=1000)

    def _vec(self, feats):
        arr = [feats[k] for k in FEATURE_KEYS]
        return np.array(arr, dtype=float).reshape(1,-1)

    def partial_fit(self, feats, label):
        x = self._vec(feats); y = np.array([label])
        if not self.first:
            self.model.partial_fit(x, y, classes=np.array([0,1]))
            self.first = True
        else:
            self.model.partial_fit(x, y)
        joblib.dump(self.model, self.path)

    def predict(self, feats):
        if not self.first:
            return 0.5
        return self.model.predict_proba(self._vec(feats))[0][1]

RISK_MODEL = RiskModel()
def extract_features(r):
    return {
        "status":    r.get("status") or 0,
        "banner_len":len(r.get("banner","") or ""),
        "n_cves":    len(r.get("cves",[])),
        "n_msf":     len(r.get("msf",[])),
        "n_mitre":   len(r.get("mitre",[])),
        "n_ceh":     len(r.get("ceh",[])),
        "secbert_avg":(
           sum(x["score"] for x in r.get("secbert",[]))
           / max(1, len(r.get("secbert",[])))
        )
    }

# ──  CORE ANALYSIS ─────────────────────────────────────────────────────────────────────────────────

class Budget:
    def __init__(self, secs): self.deadline = time.time()+secs if secs else None
    def ok(self):  return self.deadline is None or time.time()<self.deadline
    def left(self):return max(0, self.deadline-time.time()) if self.deadline else 999

def normalize_target(raw):
    if "://" not in raw:
        raw = "http://" + raw
    p = urlparse(raw)
    host = p.netloc or p.path
    return host.replace("http://","").replace("https://","").strip().lower()

from urllib.parse import urlparse

async def analyse_url(raw_target, budget, min_score):
    from urllib.parse import urlparse

    def normalize(t):
        if "://" not in t:
            t = "http://" + t
        p = urlparse(t)
        return (p.netloc or p.path).strip().lower()

    domain = normalize(raw_target)
    url = raw_target if raw_target.startswith(("http://", "https://")) else f"http://{domain}"

    rec = {
        "host": url,
        "proto": urlparse(url).scheme,
        "status": None,
        "banner": "",
        "cves": [],
        "msf": [],
        "secbert": [],
        "mitre": [],
        "ceh": [],
        "sans": []
    }
    if not budget.ok():
        return rec

    async with httpx.AsyncClient(http2=True) as cli:
        code, txt = await fetch_get(url, cli)
    rec["status"], rec["banner"] = code, txt[:500]

    rec["secbert"] = secbert_labels(rec["banner"], min_score=min_score)
    ows = [x["label"] for x in rec["secbert"]]
    rec["mitre"].extend(map_labels(ows, MITRE_MAP))
    rec["ceh"].extend(map_labels(ows, CEH_MAP))

    for m in re.findall(r"CVE-\d{4}-\d{4,7}", txt):
        rec["cves"].append({"id": m})
    if not rec["cves"]:
        for cid in extract_cves_ner(rec["banner"]):
            rec["cves"].append({"id": cid})

    for c in rec["cves"]:
        enrich_cve(c)
    rec["msf"] = msf_for([c["id"].upper() for c in rec["cves"]])

    # Aggregate MITRE, CEH, SANS from all CVEs
    rec["mitre"].extend(x for c in rec["cves"] for x in c.get("mitre", []))
    rec["ceh"].extend(x for c in rec["cves"] for x in c.get("ceh", []))
    rec["sans"] = list({c.get("sans") for c in rec["cves"] if c.get("sans")})

    rec["mitre"] = list(set(rec["mitre"]))
    rec["ceh"] = list(set(rec["ceh"]))

    feats = extract_features(rec)
    lbl = 1 if rec["cves"] else 0
    RISK_MODEL.partial_fit(feats, lbl)
    rec["risk"] = RISK_MODEL.predict(feats)

    db_add(rec)
    return rec


async def analyse_port(host, port, budget, min_score):
    rec = {
        "host": host,
        "port": port,
        "proto": "tcp",
        "banner": "",
        "cves": [],
        "msf": [],
        "secbert": [],
        "mitre": [],
        "ceh": [],
        "sans": []
    }
    if not budget.ok():
        return rec

    try:
        with socket.create_connection((host, port), timeout=3) as s:
            if port in (80, 443, 8080):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            rec["banner"] = s.recv(1024).decode(errors="ignore")
    except:
        rec["banner"] = ""

    rec["secbert"] = secbert_labels(rec["banner"], min_score=min_score)
    ows = [x["label"] for x in rec["secbert"]]
    rec["mitre"].extend(map_labels(ows, MITRE_MAP))
    rec["ceh"].extend(map_labels(ows, CEH_MAP))

    for m in re.findall(r"CVE-\d{4}-\d{4,7}", rec["banner"]):
        rec["cves"].append({"id": m})
    if not rec["cves"]:
        for cid in extract_cves_ner(rec["banner"]):
            rec["cves"].append({"id": cid})

    for c in rec["cves"]:
        enrich_cve(c)
    rec["msf"] = msf_for([c["id"].upper() for c in rec["cves"]])

    # Aggregate MITRE, CEH, SANS from CVEs
    rec["mitre"].extend(x for c in rec["cves"] for x in c.get("mitre", []))
    rec["ceh"].extend(x for c in rec["cves"] for x in c.get("ceh", []))
    rec["sans"] = list({c.get("sans") for c in rec["cves"] if c.get("sans")})

    rec["mitre"] = list(set(rec["mitre"]))
    rec["ceh"] = list(set(rec["ceh"]))

    feats = extract_features(rec)
    lbl = 1 if rec["cves"] else 0
    RISK_MODEL.partial_fit(feats, lbl)
    rec["risk"] = RISK_MODEL.predict(feats)

    db_add(rec)
    return rec





# ──  REPORT ───────────────────────────────────────────────────────────────────────────────────────

def make_report(target, results, runtime, outfile=None):
    import uuid, json, html, base64, io
    from datetime import datetime
    from pathlib import Path
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use("Agg")

    table_data = []
    for r in results:
        msf_list = [m["module"] for m in r.get("msf", []) if isinstance(m, dict)]
        table_data.append({
            "host": r["host"],
            "cves": [c["id"] for c in r["cves"]],
            "mitre": r.get("mitre", []),
            "ceh": r.get("ceh", []),
            "sans": r.get("sans", []),
            "msf": msf_list,
            "risk": round(r.get("risk", 0.0), 2),
        })

    summary = {
        "Targets": len(results),
        "With CVE": sum(bool(r["cves"]) for r in results),
        "High": sum(r.get("risk", 0) > 0.75 for r in results),
        "Medium": sum(0.4 < r.get("risk", 0) <= 0.75 for r in results),
        "Low": sum(r.get("risk", 0) <= 0.4 for r in results),
    }

    buf = io.BytesIO()
    plt.figure(figsize=(5, 3))
    plt.bar(summary.keys(), summary.values(), color=['#dc3545', '#ffc107', '#28a745', '#17a2b8', '#6c757d'])
    plt.title("Risk Summary", fontsize=14)
    plt.xticks(rotation=25)
    plt.tight_layout()
    plt.savefig(buf, format='png', dpi=120, transparent=True)
    plt.close()
    chart_base64 = base64.b64encode(buf.getvalue()).decode()

    html_id = uuid.uuid4().hex[:8]
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_code = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Enterprise Security Report</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.datatables.net/v/bs5/dt-2.0.2/b-3.0.0/b-html5-3.0.0/r-3.0.0/datatables.min.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
<style>
  body {{
    background-color: #f9f9fb;
    font-family: 'Inter', sans-serif;
    color: #333;
  }}
  .card {{
    background: #ffffff;
    border-radius: 12px;
    box-shadow: 0 2px 6px rgba(0,0,0,0.05);
    padding: 1rem 1.5rem;
    border: 1px solid #e1e4e8;
  }}
  .card h6 {{
    font-weight: 600;
    color: #2c3e50;
    margin-bottom: 0.75rem;
  }}
  .card-body canvas,
  .card-body img {{
    border-radius: 6px;
    background: #f8f9fa;
    padding: 0.5rem;
  }}
  .table thead th {{
    font-weight: 600;
    color: #444;
    background: #f0f2f5;
  }}
  .badge-low {{ background-color: #28a745 !important; }}
  .badge-med {{ background-color: #ffc107 !important; color: #000 !important; }}
  .badge-hi {{ background-color: #dc3545 !important; }}
  td {{
    word-break: break-word;
    max-width: 300px;
    white-space: normal !important;
  }}
</style>
</head>
<body>
<div class="container-fluid py-4">
  <h1 class="mb-2">AI-SA Enterprise Vulnerability Report</h1>
  <p class="text-muted">Target: <strong>{html.escape(target)}</strong> · Duration: {runtime:.1f}s · Generated: {now}</p>

  <div class="row g-4 mb-4">
    <div class="col-md-4">
      <div class="card">
        <h6>Scan Summary</h6>
        <img src="data:image/png;base64,{chart_base64}" class="img-fluid" alt="Summary Chart">
      </div>
    </div>
    <div class="col-md-8">
      <div class="card">
        <h6>Risk Breakdown</h6>
        <div style="position:relative; width:100%; max-width:260px; margin:auto;">
          <canvas id="riskChart{html_id}"></canvas>
        </div>
      </div>
    </div>
  </div>

  <div class="card">
    <h6 class="mb-3">Detailed Findings</h6>
    <table id="reportTable{html_id}" class="table table-sm table-hover nowrap w-100">
      <thead>
        <tr>
          <th>Host</th>
          <th>CVEs</th>
          <th>MITRE</th>
          <th>CEH</th>
          <th>SANS</th>
          <th>Metasploit</th>
          <th>Risk</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
  </div>
</div>

<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script src="https://cdn.datatables.net/v/bs5/dt-2.0.2/b-3.0.0/b-html5-3.0.0/r-3.0.0/datatables.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/pdfmake.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/vfs_fonts.js"></script>

<script>
const data = {json.dumps(table_data)};
const riskCounts = {{
  "High": data.filter(function(r) {{ return r.risk > 0.75; }}).length,
  "Medium": data.filter(function(r) {{ return r.risk > 0.4 && r.risk <= 0.75; }}).length,
  "Low": data.filter(function(r) {{ return r.risk <= 0.4; }}).length
}};

new Chart(document.getElementById("riskChart{html_id}"), {{
  type: "doughnut",
  data: {{
    labels: Object.keys(riskCounts),
    datasets: [{{
      data: Object.values(riskCounts),
      backgroundColor: ["#dc3545", "#ffc107", "#28a745"]
    }}]
  }},
  options: {{
    plugins: {{
      legend: {{
        position: "bottom",
        labels: {{ color: "#333" }}
      }}
    }},
    cutout: "65%"
  }}
}});

$(document).ready(function() {{
  $('#reportTable{html_id}').DataTable({{
    data: data,
    columns: [
      {{ data: 'host' }},
      {{ data: 'cves', render: function(d) {{
        return d.map(function(x) {{
          return '<a href="https://nvd.nist.gov/vuln/detail/' + x + '" target="_blank">' + x + '</a>';
        }}).join('<br>');
      }} }},
      {{ data: 'mitre', render: function(d) {{
        return d.map(function(x) {{
          return '<a href="https://attack.mitre.org/techniques/' + x + '/" target="_blank">' + x + '</a>';
        }}).join('<br>');
      }} }},
      {{ data: 'ceh', render: function(d) {{ return d.join('<br>'); }} }},
      {{ data: 'sans', render: function(d) {{ return d.join('<br>'); }} }},
      {{ data: 'msf', render: function(d) {{
        return d.length ? d.map(function(x) {{
          return '<span class="d-block">' + x + '</span>';
        }}).join('') : '—';
      }} }},
      {{ data: 'risk', render: function(v) {{
        var badge = 'low';
        if (v > 0.75) badge = 'hi';
        else if (v > 0.4) badge = 'med';
        return '<span class="badge badge-' + badge + '">' + v + '</span>';
      }} }}
    ],
    dom: 'Bfrtip',
    buttons: [
      'copy',
      'csv',
      'excel',
      {{
        extend: 'pdfHtml5',
        orientation: 'landscape',
        pageSize: 'A4',
        exportOptions: {{ columns: ':visible' }}
      }},
      'print'
    ],
    responsive: true,
    pagingType: 'numbers',
    order: [[6, 'desc']],
    searchHighlight: true,
    scrollX: true
  }});
}});
</script>
</body>
</html>
"""

    if outfile:
        Path(outfile).write_text(html_code, encoding="utf-8")
    else:
        print(html_code)




# ──  CLI & MAIN ───────────────────────────────────────────────────────────────────────────────────

def parse_ports(s):
    out=set()
    if not s: return []
    for seg in s.split(","):
        if "-" in seg:
            a,b=map(int,seg.split("-",1)); out.update(range(min(a,b),max(a,b)+1))
        else:
            out.add(int(seg))
    return sorted(p for p in out if 0<p<65536)

async def main_scan(args):
    budget=Budget(args.time_budget)
    tasks,results=[],[]
    if args.auto_subs:
        for sub in enum_subs(args.target)[:args.sub_limit]:
            tasks.append(analyse_url(f"http://{sub}.{args.target}",budget,args.min_score))
    if args.ports:
        for p in parse_ports(args.ports):
            tasks.append(analyse_port(args.target,p,budget,args.min_score))
    else:
        tasks.append(analyse_url(args.target,budget,args.min_score))

    for coro in asyncio.as_completed(tasks):
        if not budget.ok(): break
        results.append(await coro)

    make_report(args.target, results, args.time_budget-budget.left(), args.out)

def cli():
    p=argparse.ArgumentParser("AISA-Scanner | Haroon Ahmad Awan | haroon@cyberzeus.pk")
    p.add_argument("-t","--target", required=True, help="domain or IP")
    p.add_argument("-P","--ports", help="e.g. 22,80-85")
    p.add_argument("--auto-subs", action="store_true", help="enumerate common subdomains")
    p.add_argument("--sub-limit", type=int, default=50)
    p.add_argument("--time-budget", type=int, default=30)
    p.add_argument("--min-score", type=float, default=0.90, help="confidence threshold")
    p.add_argument("--out", help="write HTML report")
    args=p.parse_args()
    db_init()
    asyncio.run(main_scan(args))

if __name__=="__main__":
    cli()
