#!/usr/bin/env python3
"""CyberWatch Africa PRO 6.0 — defensive threat-intelligence dashboard for Termux."""
from __future__ import annotations
import csv, ipaddress, json, os, queue, socket, sqlite3, threading, time, urllib.request
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("CW_DB", str(Path.home() / "cyberwatch_africa_v5.db")))
HOST = os.getenv("CW_HOST", "127.0.0.1")
PORT = int(os.getenv("CW_PORT", "8080"))
REFRESH = max(180, int(os.getenv("CW_REFRESH", "300")))
HOME = {"name": os.getenv("HOME_NAME", "Abidjan"),
        "lat": float(os.getenv("HOME_LAT", "5.36")),
        "lon": float(os.getenv("HOME_LON", "-4.01"))}
WATCH = {x.strip().upper() for x in os.getenv("WATCH", "CI,SN,GH,NG").split(",") if x.strip()}
ENABLE_HONEYPOT = os.getenv("CW_HONEYPOT", "0") == "1"
HONEYPOT_PORT = int(os.getenv("CW_HONEYPOT_PORT", "2222"))
TG_TOKEN, TG_CHAT = os.getenv("TG_TOKEN"), os.getenv("TG_CHAT")
MAX_GEO_PER_CYCLE = 90
USER_AGENT = "CyberWatch-Africa-PRO/6.0 (defensive threat intelligence)"
SOURCES = [
    ("Feodo Tracker", "https://feodotracker.abuse.ch/downloads/ipblocklist.json", "feodo"),
    ("Blocklist.de", "https://lists.blocklist.de/lists/all.txt", "bruteforce"),
    ("Emerging Threats", "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt", "scan"),
]
state_lock = threading.RLock()
geo_lock = threading.Lock()
stop_event = threading.Event()
geo_cache: dict[str, dict | None] = {}
last_errors: list[str] = []
runtime = {"last_update": None, "collecting": False, "source_status": {},
           "local_scan": {"status": "Pas encore exécuté", "devices": []},
           "device_info": {"status": "Diagnostic non exécuté"}}

def now_utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def db():
    con = sqlite3.connect(DB_PATH, timeout=20)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS threats(
          ip TEXT NOT NULL, source TEXT NOT NULL, kind TEXT NOT NULL,
          label TEXT, country TEXT, country_code TEXT, city TEXT,
          lat REAL, lon REAL, continent TEXT, first_seen TEXT, last_seen TEXT,
          PRIMARY KEY(ip, source));
        CREATE TABLE IF NOT EXISTS events(
          id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, severity TEXT NOT NULL,
          category TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL, ip TEXT);
        CREATE TABLE IF NOT EXISTS geo_cache(
          ip TEXT PRIMARY KEY, payload TEXT, checked_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS local_devices(
          ip TEXT PRIMARY KEY, hostname TEXT, first_seen TEXT, last_seen TEXT);
        CREATE TABLE IF NOT EXISTS scan_runs(
          id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, subnet TEXT, found INTEGER, note TEXT);
        """)

def http_get(url, data=None, timeout=20):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT,
        "Content-Type": "application/json" if data else "text/plain"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")

def public_ip(value):
    try:
        obj = ipaddress.ip_address(str(value).strip())
        return str(obj) if obj.is_global else None
    except ValueError:
        return None

def parse_feed(body, feed_type):
    found = []
    if feed_type == "feodo":
        try:
            obj = json.loads(body)
            rows = obj if isinstance(obj, list) else obj.get("data", [])
            for row in rows:
                ip = public_ip(row.get("ip_address", ""))
                if ip:
                    found.append((ip, row.get("malware") or "botnet"))
        except (ValueError, TypeError, AttributeError):
            pass
    else:
        kind = "brute-force" if feed_type == "bruteforce" else "scan/attaque"
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            ip = public_ip(line.split()[0].split("/")[0])
            if ip:
                found.append((ip, kind))
    return found

def load_geo_cache():
    with db() as con:
        for row in con.execute("SELECT ip,payload FROM geo_cache"):
            try:
                geo_cache[row["ip"]] = json.loads(row["payload"]) if row["payload"] else None
            except ValueError:
                continue

def geolocate(ips, errors):
    with geo_lock:
        todo = [ip for ip in dict.fromkeys(ips) if ip not in geo_cache][:MAX_GEO_PER_CYCLE]
        if not todo:
            return
        try:
            # ip-api free batch endpoint: batches <=100; do not exceed our conservative cycle cap.
            data = json.loads(http_get(
                "http://ip-api.com/batch?fields=status,country,countryCode,city,lat,lon,continent,continentCode,query",
                json.dumps(todo).encode(), timeout=25))
            stamp = now_utc()
            with db() as con:
                for item in data:
                    ip = item.get("query")
                    val = item if item.get("status") == "success" else None
                    geo_cache[ip] = val
                    con.execute("INSERT OR REPLACE INTO geo_cache(ip,payload,checked_at) VALUES(?,?,?)",
                                (ip, json.dumps(val) if val else None, stamp))
        except Exception as exc:
            errors.append("Géolocalisation : " + str(exc))

def severity_for(kind):
    return {"botnet": "Élevé", "brute-force": "Élevé",
            "scan/attaque": "Moyen", "honeypot": "À examiner"}.get(kind, "Faible")

def record_event(severity, category, title, detail, ip=None):
    with db() as con:
        con.execute("INSERT INTO events(ts,severity,category,title,detail,ip) VALUES(?,?,?,?,?,?)",
                    (now_utc(), severity, category, title, detail, ip))

def notify(title, message):
    try:
        import subprocess
        subprocess.run(["termux-notification", "--title", title, "--content", message],
                       timeout=8, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def telegram(message):
    if not TG_TOKEN or not TG_CHAT:
        return
    try:
        http_get("https://api.telegram.org/bot" + TG_TOKEN + "/sendMessage",
                 json.dumps({"chat_id": TG_CHAT, "text": message}).encode(), timeout=12)
    except Exception:
        pass

def collect_cycle():
    errors, source_status, records = [], {}, {}
    with state_lock:
        runtime["collecting"] = True
        runtime["source_status"] = {name: {"ok": None, "count": 0, "checked": "En cours…"} for name, _, _ in SOURCES}
    for name, url, typ in SOURCES:
        try:
            rows = parse_feed(http_get(url, timeout=22), typ)
            source_status[name] = {"ok": True, "count": len(rows), "checked": now_utc()}
            with state_lock: runtime["source_status"] = dict(source_status)
            for ip, label in rows:
                kind = "botnet" if typ == "feodo" else label
                records.setdefault((ip, name), (kind, label))
        except Exception as exc:
            source_status[name] = {"ok": False, "count": 0, "error": str(exc)[:180]}
            errors.append(f"{name}: {exc}")
            with state_lock: runtime["source_status"] = dict(source_status)

    current = now_utc()
    new_africa = []
    geolocate([ip for ip, _ in records], errors)
    with db() as con:
        for (ip, source), (kind, label) in records.items():
            g = geo_cache.get(ip)
            if not g:
                continue
            old = con.execute("SELECT first_seen FROM threats WHERE ip=? AND source=?", (ip, source)).fetchone()
            first = old["first_seen"] if old else current
            con.execute("""INSERT OR REPLACE INTO threats
              (ip,source,kind,label,country,country_code,city,lat,lon,continent,first_seen,last_seen)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
              (ip, source, kind, label, g.get("country"), g.get("countryCode"), g.get("city"),
               g.get("lat"), g.get("lon"), g.get("continentCode"), first, current))
            if not old and g.get("continentCode") == "AF" and (not WATCH or g.get("countryCode") in WATCH):
                new_africa.append((ip, g.get("country", "Pays inconnu"), kind))
        # Remove stale source entries only after successful source collection, not on outages.
        for name, status in source_status.items():
            if status["ok"]:
                # Keep historical observations; last_seen remains useful for recency filters.
                pass

    for ip, country, kind in new_africa:
        msg = f"Nouvelle IP signalée : {ip} ({country}) — {kind}"
        record_event(severity_for(kind), "Threat feed", "Nouvelle IP signalée", msg, ip)
        notify("CyberWatch Africa", msg)
        telegram(msg)

    with state_lock:
        runtime["last_update"] = current
        runtime["source_status"] = source_status
        runtime["collecting"] = False
        last_errors[:] = errors
    return {"sources": source_status, "errors": errors, "new_africa": len(new_africa)}

def background_loop():
    while not stop_event.is_set():
        with state_lock:
            runtime["collecting"] = True
        try:
            collect_cycle()
        except Exception as exc:
            with state_lock:
                runtime["collecting"] = False
                last_errors[:] = [str(exc)]
        stop_event.wait(REFRESH)

def stats_data():
    with db() as con:
        recent_48h = datetime.fromtimestamp(time.time()-172800, timezone.utc).isoformat(timespec="seconds")
        total = con.execute("SELECT COUNT(DISTINCT ip) FROM threats WHERE last_seen >= ?", (recent_48h,)).fetchone()[0]
        africa = con.execute("SELECT COUNT(DISTINCT ip) FROM threats WHERE continent='AF' AND last_seen >= ?", (recent_48h,)).fetchone()[0]
        cutoff = datetime.fromtimestamp(time.time()-3600, timezone.utc).isoformat(timespec="seconds")
        new_hour = con.execute("SELECT COUNT(DISTINCT ip) FROM threats WHERE first_seen >= ?", (cutoff,)).fetchone()[0]
        by_country = con.execute("""SELECT country,COUNT(DISTINCT ip) n FROM threats
            WHERE continent='AF' AND last_seen >= ? GROUP BY country ORDER BY n DESC LIMIT 10""",
            (datetime.fromtimestamp(time.time()-86400, timezone.utc).isoformat(timespec="seconds"),)).fetchall()
        world = con.execute("""SELECT country,COUNT(DISTINCT ip) n FROM threats
            WHERE last_seen >= ? GROUP BY country ORDER BY n DESC LIMIT 10""",
            (datetime.fromtimestamp(time.time()-86400, timezone.utc).isoformat(timespec="seconds"),)).fetchall()
        kinds = con.execute("SELECT kind,COUNT(DISTINCT ip) n FROM threats GROUP BY kind ORDER BY n DESC").fetchall()
        days = con.execute("""SELECT substr(last_seen,1,10) day,COUNT(DISTINCT ip) n,
            COUNT(DISTINCT CASE WHEN continent='AF' THEN ip END) af
            FROM threats GROUP BY day ORDER BY day DESC LIMIT 30""").fetchall()
        events = con.execute("SELECT COUNT(*) FROM events WHERE ts >= ?",
            (datetime.fromtimestamp(time.time()-86400, timezone.utc).isoformat(timespec="seconds"),)).fetchone()[0]
        return {"total": total, "africa": africa, "new_1h": new_hour, "events_24h": events,
                "top_africa": [list(r) for r in by_country], "top_world": [list(r) for r in world],
                "kinds": [list(r) for r in kinds], "history": [list(r) for r in days]}

def risk_score(kind, sources=1):
    base = {"botnet": 90, "brute-force": 78, "scan/attaque": 55, "honeypot": 65}.get(kind, 30)
    return min(100, base + max(0, sources-1)*8)

def points_data():
    with db() as con:
        rows = con.execute("""SELECT ip,source src,kind,label,lat,lon,country cc,country,city,
            continent,first_seen,last_seen FROM threats
            WHERE last_seen >= ? ORDER BY last_seen DESC LIMIT 1500""",
            (datetime.fromtimestamp(time.time()-86400, timezone.utc).isoformat(timespec="seconds"),)).fetchall()
        pts = [dict(r) for r in rows]
    for p in pts:
        p["africa"] = p.pop("continent") == "AF"
        p["risk"] = risk_score(p["kind"])
    with state_lock:
        # Honeypot entries are persisted in events; do not fabricate map points.
        return pts

def events_data(limit=100):
    with db() as con:
        return [dict(r) for r in con.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))]

def investigate_ip(value):
    ip = public_ip(value)
    if not ip:
        raise ValueError("Adresse IP publique invalide. Les IP privées ne sont pas géolocalisées.")
    errors = []
    geolocate([ip], errors)
    g = geo_cache.get(ip)
    try:
        host = socket.gethostbyaddr(ip)[0]
    except Exception:
        host = None
    with db() as con:
        matches = [dict(r) for r in con.execute("SELECT source,kind,label,first_seen,last_seen FROM threats WHERE ip=?", (ip,))]
    return {"ip": ip, "geo": g, "reverse_dns": host, "listed": bool(matches),
            "matches": matches, "notes": errors}

def local_network_scan():
    # Discovery only: ICMP/ping is not required. Probe TCP 80/443/22 on hosts
    # within the user's connected private /24; never targets public ranges.
    try:
        import ipaddress
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 80))
        local_ip = s.getsockname()[0]
        s.close()
        addr = ipaddress.ip_address(local_ip)
        if not addr.is_private:
            raise RuntimeError("L'adresse détectée n'est pas privée.")
        net = ipaddress.ip_network(local_ip + "/24", strict=False)
        devices = []
        for host in list(net.hosts())[:254]:
            target = str(host)
            if target == local_ip:
                devices.append({"ip": target, "hostname": socket.gethostname(), "self": True})
                continue
            opened = []
            for port in (80, 443, 22):
                sock = socket.socket()
                sock.settimeout(0.18)
                try:
                    if sock.connect_ex((target, port)) == 0:
                        opened.append(port)
                except OSError:
                    pass
                finally:
                    sock.close()
            if opened:
                try: name = socket.gethostbyaddr(target)[0]
                except Exception: name = ""
                devices.append({"ip": target, "hostname": name, "ports": opened})
        stamp = now_utc()
        with db() as con:
            for d in devices:
                con.execute("INSERT OR REPLACE INTO local_devices VALUES(?,?,COALESCE((SELECT first_seen FROM local_devices WHERE ip=?),?),?)",
                            (d["ip"], d.get("hostname",""), d["ip"], stamp, stamp))
            con.execute("INSERT INTO scan_runs(ts,subnet,found,note) VALUES(?,?,?,?)",
                        (stamp, str(net), len(devices), "Découverte TCP limitée aux ports 22, 80, 443"))
        result = {"status": f"Terminé — {len(devices)} appareil(s) répondent sur les ports testés",
                  "subnet": str(net), "devices": devices}
    except Exception as exc:
        result = {"status": "Échec : " + str(exc), "devices": []}
    with state_lock:
        runtime["local_scan"] = result
    return result

def export_csv():
    with db() as con:
        rows = con.execute("SELECT * FROM threats ORDER BY last_seen DESC").fetchall()
    import io
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["ip","source","type","label","country","country_code","city","latitude","longitude","first_seen_utc","last_seen_utc"])
    for r in rows:
        writer.writerow([r["ip"],r["source"],r["kind"],r["label"],r["country"],r["country_code"],
                         r["city"],r["lat"],r["lon"],r["first_seen"],r["last_seen"]])
    return out.getvalue().encode("utf-8-sig")

def export_json():
    with db() as con:
        threats = [dict(r) for r in con.execute("SELECT * FROM threats ORDER BY last_seen DESC")]
        events = [dict(r) for r in con.execute("SELECT * FROM events ORDER BY id DESC LIMIT 1000")]
    payload = {"generated_at_utc": now_utc(), "notice": "IP threat-intel indicators are not proof of attacks against a specific target; geolocation is approximate.", "threats": threats, "events": events}
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")

def device_diagnostics():
    import platform
    info = {"platform": platform.platform(), "python": platform.python_version(),
            "hostname": socket.gethostname(), "local_ip": None, "dns": "Non testé", "internet": False,
            "limits": "Termux ne fournit pas à Python un accès complet au trafic Android sans VPN local, permissions adaptées ou root."}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.connect(("1.1.1.1", 53))
        info["local_ip"] = sock.getsockname()[0]; sock.close()
    except OSError: pass
    try:
        socket.gethostbyname("example.com"); info["dns"] = "Fonctionnel"
    except OSError: info["dns"] = "Échec de résolution"
    try:
        http_get("https://www.google.com/generate_204", timeout=6); info["internet"] = True
    except Exception: pass
    info["status"] = "Diagnostic terminé"
    with state_lock: runtime["device_info"] = info
    return info

def report_html():
    d = json_payload(); st = d["stats"]
    rows = "".join(f"<tr><td>{html_escape(str(x[0]))}</td><td>{x[1]}</td></tr>" for x in st["top_africa"])
    ev = "".join(f"<tr><td>{html_escape(e['ts'])}</td><td>{html_escape(e['severity'])}</td><td>{html_escape(e['title'])}</td><td>{html_escape(e['ip'] or '')}</td></tr>" for e in d["events"][:50])
    return ("<!doctype html><html lang='fr'><meta charset='utf-8'><title>Rapport CyberWatch</title>"
      "<style>body{font:14px Arial;margin:35px;color:#18202b}h1{color:#075e59}table{border-collapse:collapse;width:100%;margin:15px 0}td,th{border:1px solid #bbb;padding:7px;text-align:left}button{padding:10px}@media print{button{display:none}}</style>"
      f"<h1>CyberWatch Africa PRO 6.0 — Rapport</h1><p>Généré le {html_escape(now_utc())} (UTC). Données indicatives issues de flux publics.</p>"
      f"<p>IP distinctes (48 h) : <b>{st['total']}</b> — IP géolocalisées en Afrique : <b>{st['africa']}</b> — Incidents (24 h) : <b>{st['events_24h']}</b></p>"
      f"<h2>Pays africains les plus représentés</h2><table><tr><th>Pays</th><th>IP</th></tr>{rows}</table>"
      f"<h2>Journal récent</h2><table><tr><th>Date UTC</th><th>Gravité</th><th>Événement</th><th>IP</th></tr>{ev}</table>"
      "<p>Une IP de threat-intel n'est pas une preuve d'attaque contre cet appareil. Géolocalisation approximative.</p><button onclick='window.print()'>Imprimer / Enregistrer en PDF</button></html>").encode()

def html_escape(value):
    import html
    return html.escape(str(value))

def json_payload():
    with state_lock:
        status = {"last_update": runtime["last_update"], "collecting": runtime["collecting"],
                  "source_status": runtime["source_status"], "errors": list(last_errors),
                  "local_scan": runtime["local_scan"], "device_info": runtime["device_info"]}
    return {"stats": stats_data(), "points": points_data(), "events": events_data(60), "runtime": status,
            "home": HOME, "refresh_seconds": REFRESH}

class Handler(BaseHTTPRequestHandler):
    def reply(self, code, body, ctype="application/json; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self' https: data: 'unsafe-inline'; img-src 'self' https: data:")
        self.end_headers()
        try: self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError): pass
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self.reply(200, (ROOT/"static"/"index.html").read_bytes(), "text/html; charset=utf-8")
        elif path == "/app.js":
            self.reply(200, (ROOT/"static"/"app.js").read_bytes(), "application/javascript; charset=utf-8")
        elif path == "/style.css":
            self.reply(200, (ROOT/"static"/"style.css").read_bytes(), "text/css; charset=utf-8")
        elif path == "/api/data":
            self.reply(200, json.dumps(json_payload()).encode())
        elif path == "/api/events":
            self.reply(200, json.dumps(events_data(200)).encode())
        elif path == "/api/investigate":
            ip = parse_qs(urlparse(self.path).query).get("ip", [""])[0]
            try: self.reply(200, json.dumps(investigate_ip(ip)).encode())
            except ValueError as exc: self.reply(400, json.dumps({"error":str(exc)}).encode())
        elif path == "/api/export.csv":
            self.reply(200, export_csv(), "text/csv; charset=utf-8")
        elif path == "/api/export.json":
            self.reply(200, export_json(), "application/json; charset=utf-8")
        elif path == "/api/report":
            self.reply(200, report_html(), "text/html; charset=utf-8")
        else:
            self.reply(404, b'{"error":"Not found"}')
    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/refresh":
            threading.Thread(target=collect_cycle, daemon=True).start()
            self.reply(202, b'{"status":"Collecte demandee"}')
        elif path == "/api/local-scan":
            threading.Thread(target=local_network_scan, daemon=True).start()
            self.reply(202, b'{"status":"Analyse locale demarree"}')
        elif path == "/api/device-diagnostics":
            threading.Thread(target=device_diagnostics, daemon=True).start()
            self.reply(202, b'{"status":"Diagnostic demarre"}')
        else:
            self.reply(404, b'{"error":"Not found"}')
    def log_message(self, *args): pass

def main():
    init_db()
    load_geo_cache()
    threading.Thread(target=background_loop, daemon=True).start()
    print("\\n CYBERWATCH AFRICA PRO 6.0")
    print(f" Tableau : http://127.0.0.1:{PORT}")
    print(f" Base : {DB_PATH}")
    print(f" Cycle : {REFRESH}s | Honeypot : {'ACTIF' if ENABLE_HONEYPOT else 'désactivé'}")
    print(" Version : 6.0 | Cybermap Afrique + arcs visuels explicitement illustratifs")
    if ENABLE_HONEYPOT:
        threading.Thread(target=honeypot_server, daemon=True).start()
    try:
        ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        stop_event.set()
        print("\\nArrêt de CyberWatch Africa.")

def honeypot_server():
    # Listener passif minimal, facultatif. Ne collecte que bannière client SSH.
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", HONEYPOT_PORT)); sock.listen(10)
        print(f"[HONEYPOT] Port {HONEYPOT_PORT}")
    except OSError as exc:
        print("[HONEYPOT] Désactivé :", exc); return
    while not stop_event.is_set():
        try: conn, addr = sock.accept()
        except OSError: break
        threading.Thread(target=honeypot_client, args=(conn, addr), daemon=True).start()

def honeypot_client(conn, addr):
    ip = public_ip(addr[0])
    banner = ""
    try:
        conn.settimeout(4); conn.sendall(b"SSH-2.0-CyberWatch-Research\\r\\n")
        banner = conn.recv(128).decode("ascii","ignore").strip()[:80]
    except Exception: pass
    finally: conn.close()
    if ip:
        record_event("À examiner","Honeypot","Connexion entrante observée",banner or "Bannière absente",ip)
        notify("CyberWatch honeypot", f"Connexion observée depuis {ip}")

if __name__ == "__main__":
    main()
