#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║          DOMAIN INVESTIGATOR - Herramienta OSINT v1.0            ║
║     Análisis de reputación, DNS, WHOIS y amenazas de dominio     ║
╚══════════════════════════════════════════════════════════════════╝

APIs utilizadas:
  - VirusTotal       → Reputación y listas negras
  - AbuseIPDB        → Reputación de IP
  - URLScan.io       → Escaneo de URL/dominio
  - Shodan           → Puertos y servicios expuestos
  - ip-api.com       → Geolocalización de IP (sin clave)
  - DNS nativo       → SPF, DKIM, DMARC, MX, NS, A
  - python-whois     → WHOIS y fecha de creación
  - SSL nativo       → Información del certificado TLS
"""

import sys
import os
import json
import socket
import ssl
import ipaddress
import datetime
import time
import re
import hashlib
import base64
from typing import Optional
import argparse
import configparser

# ── Dependencias externas ─────────────────────────────────────────
try:
    import requests
    import dns.resolver
    import whois
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.columns import Columns
    from rich.text import Text
    from rich.rule import Rule
    from rich import box
    from rich.layout import Layout
    from rich.align import Align
    from rich.padding import Padding
    from rich.markdown import Markdown
except ImportError as e:
    print(f"\n[ERROR] Falta dependencia: {e}")
    print("Instala con:  pip install -r requirements.txt\n")
    sys.exit(1)

console = Console()

# ═══════════════════════════════════════════════════════════════════
#  CONFIGURACIÓN DE API KEYS
# ═══════════════════════════════════════════════════════════════════

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.ini")

def load_config() -> dict:
    """Carga claves API desde config.ini o variables de entorno."""
    config = {
        "VIRUSTOTAL_API_KEY": "",
        "ABUSEIPDB_API_KEY": "",
        "URLSCAN_API_KEY": "",
        "SHODAN_API_KEY": "",
    }
    # Desde archivo
    if os.path.exists(CONFIG_FILE):
        parser = configparser.ConfigParser()
        parser.read(CONFIG_FILE)
        if "API_KEYS" in parser:
            for key in config:
                config[key] = parser["API_KEYS"].get(key, "")
    # Variables de entorno tienen prioridad
    for key in config:
        env_val = os.environ.get(key, "")
        if env_val:
            config[key] = env_val
    return config

# ═══════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════

TIMEOUT = 10

def safe_get(url: str, headers: dict = None, params: dict = None) -> Optional[dict]:
    """GET con manejo de errores. Retorna JSON o None."""
    try:
        r = requests.get(url, headers=headers, params=params, timeout=TIMEOUT)
        if r.status_code == 200:
            return r.json()
        return {"_status_code": r.status_code, "_error": r.text[:200]}
    except requests.RequestException as e:
        return {"_error": str(e)}

def safe_post(url: str, headers: dict = None, data=None, json_data=None) -> Optional[dict]:
    try:
        r = requests.post(url, headers=headers, data=data, json=json_data, timeout=TIMEOUT)
        if r.status_code in (200, 201):
            return r.json()
        return {"_status_code": r.status_code, "_error": r.text[:200]}
    except requests.RequestException as e:
        return {"_error": str(e)}

def risk_badge(score: int) -> Text:
    """Genera badge de riesgo coloreado según puntuación 0-100."""
    if score >= 75:
        return Text(f" ● CRÍTICO ({score}/100) ", style="bold white on red")
    elif score >= 50:
        return Text(f" ● ALTO ({score}/100) ", style="bold white on dark_orange")
    elif score >= 25:
        return Text(f" ● MEDIO ({score}/100) ", style="bold black on yellow")
    elif score > 0:
        return Text(f" ● BAJO ({score}/100) ", style="bold white on blue")
    else:
        return Text(f" ● LIMPIO (0/100) ", style="bold white on green")

def check_icon(value: bool) -> str:
    return "✅" if value else "❌"

def na_if_empty(val, default="N/A") -> str:
    if val is None or val == "" or val == []:
        return default
    if isinstance(val, list):
        return ", ".join(str(v) for v in val[:3])
    return str(val)

# ═══════════════════════════════════════════════════════════════════
#  MÓDULO 1: RESOLUCIÓN DNS BÁSICA
# ═══════════════════════════════════════════════════════════════════

def resolve_domain(domain: str) -> dict:
    result = {"ips": [], "ipv6": [], "ns": [], "mx": [], "error": None}
    try:
        # A records
        answers = dns.resolver.resolve(domain, "A")
        result["ips"] = [r.address for r in answers]
    except Exception:
        try:
            result["ips"] = [socket.gethostbyname(domain)]
        except Exception as e:
            result["error"] = str(e)
    try:
        answers = dns.resolver.resolve(domain, "AAAA")
        result["ipv6"] = [r.address for r in answers]
    except Exception:
        pass
    try:
        answers = dns.resolver.resolve(domain, "NS")
        result["ns"] = [str(r.target).rstrip(".") for r in answers]
    except Exception:
        pass
    try:
        answers = dns.resolver.resolve(domain, "MX")
        result["mx"] = [f"{r.preference} {str(r.exchange).rstrip('.')}" for r in answers]
    except Exception:
        pass
    return result

# ═══════════════════════════════════════════════════════════════════
#  MÓDULO 2: SPF / DKIM / DMARC
# ═══════════════════════════════════════════════════════════════════

def check_email_security(domain: str) -> dict:
    result = {
        "spf": {"found": False, "record": None, "policy": None},
        "dmarc": {"found": False, "record": None, "policy": None, "rua": None},
        "dkim": {"selectors_found": [], "selectors_checked": []},
    }

    # ── SPF ────────────────────────────────────────────────────────
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if txt.startswith("v=spf1"):
                result["spf"]["found"] = True
                result["spf"]["record"] = txt
                if "~all" in txt:
                    result["spf"]["policy"] = "SoftFail (~all) — advertencia, no bloquea"
                elif "-all" in txt:
                    result["spf"]["policy"] = "HardFail (-all) — rechaza no autorizados ✅"
                elif "+all" in txt:
                    result["spf"]["policy"] = "⚠️  Pass (+all) — peligroso, acepta TODO"
                elif "?all" in txt:
                    result["spf"]["policy"] = "Neutral (?all) — sin política definida"
                else:
                    result["spf"]["policy"] = "Sin mecanismo 'all'"
    except Exception:
        pass

    # ── DMARC ──────────────────────────────────────────────────────
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if txt.startswith("v=DMARC1"):
                result["dmarc"]["found"] = True
                result["dmarc"]["record"] = txt
                m = re.search(r"p=(\w+)", txt)
                if m:
                    p = m.group(1).lower()
                    labels = {"none": "none — solo monitoreo (débil)",
                              "quarantine": "quarantine — mover a spam",
                              "reject": "reject — rechazar (óptimo) ✅"}
                    result["dmarc"]["policy"] = labels.get(p, p)
                rua = re.search(r"rua=([^\s;]+)", txt)
                if rua:
                    result["dmarc"]["rua"] = rua.group(1)
    except Exception:
        pass

    # ── DKIM (selectores comunes) ──────────────────────────────────
    common_selectors = [
        "default", "google", "mail", "email", "dkim", "selector1",
        "selector2", "k1", "s1", "s2", "smtp", "mimecast",
        "protonmail", "pm", "mandrill", "sendgrid", "mailchimp",
    ]
    result["dkim"]["selectors_checked"] = common_selectors
    for sel in common_selectors:
        try:
            answers = dns.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
            for rdata in answers:
                txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                if "p=" in txt:
                    result["dkim"]["selectors_found"].append(sel)
                    break
        except Exception:
            pass
    return result

# ═══════════════════════════════════════════════════════════════════
#  MÓDULO 3: WHOIS
# ═══════════════════════════════════════════════════════════════════

def get_whois(domain: str) -> dict:
    result = {
        "registrar": None, "created": None, "updated": None,
        "expires": None, "status": [], "name_servers": [],
        "country": None, "age_days": None, "raw_error": None,
    }
    try:
        w = whois.whois(domain)
        result["registrar"] = na_if_empty(w.registrar)
        result["country"] = na_if_empty(getattr(w, "country", None))
        result["status"] = w.status if isinstance(w.status, list) else [w.status] if w.status else []
        result["name_servers"] = (
            [ns.lower() for ns in w.name_servers]
            if isinstance(w.name_servers, list)
            else []
        )
        # Fechas
        def parse_date(d):
            if isinstance(d, list):
                d = d[0]
            if isinstance(d, datetime.datetime):
                return d
            return None

        created = parse_date(w.creation_date)
        expires = parse_date(w.expiration_date)
        updated = parse_date(w.updated_date)

        result["created"] = created.strftime("%Y-%m-%d") if created else None
        result["expires"] = expires.strftime("%Y-%m-%d") if expires else None
        result["updated"] = updated.strftime("%Y-%m-%d") if updated else None

        if created:
            result["age_days"] = (datetime.datetime.utcnow() - created).days
    except Exception as e:
        result["raw_error"] = str(e)
    return result

# ═══════════════════════════════════════════════════════════════════
#  MÓDULO 4: VIRUSTOTAL
# ═══════════════════════════════════════════════════════════════════

def check_virustotal(domain: str, api_key: str) -> dict:
    if not api_key:
        return {"_skip": True, "_reason": "API key no configurada"}

    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    data = safe_get(url, headers=headers)

    if not data or "_error" in data:
        return {"_error": data.get("_error", "Error desconocido") if data else "Sin respuesta"}

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    votes = attrs.get("total_votes", {})

    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation", 0),
        "categories": attrs.get("categories", {}),
        "votes_harmless": votes.get("harmless", 0),
        "votes_malicious": votes.get("malicious", 0),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "tags": attrs.get("tags", []),
        "registrar": attrs.get("registrar", ""),
    }

# ═══════════════════════════════════════════════════════════════════
#  MÓDULO 5: ABUSEIPDB
# ═══════════════════════════════════════════════════════════════════

def check_abuseipdb(ip: str, api_key: str) -> dict:
    if not api_key:
        return {"_skip": True, "_reason": "API key no configurada"}
    if not ip:
        return {"_error": "IP no disponible"}

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}
    data = safe_get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)

    if not data or "_error" in data:
        return {"_error": data.get("_error", "Error") if data else "Sin respuesta"}

    d = data.get("data", {})
    return {
        "ip": d.get("ipAddress"),
        "abuse_score": d.get("abuseConfidenceScore", 0),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "domain": d.get("domain"),
        "total_reports": d.get("totalReports", 0),
        "num_distinct_users": d.get("numDistinctUsers", 0),
        "last_reported": d.get("lastReportedAt"),
        "is_whitelisted": d.get("isWhitelisted", False),
        "usage_type": d.get("usageType"),
    }

# ═══════════════════════════════════════════════════════════════════
#  MÓDULO 6: URLSCAN.IO
# ═══════════════════════════════════════════════════════════════════

def check_urlscan(domain: str, api_key: str) -> dict:
    """Busca el último escaneo disponible para el dominio."""
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["API-Key"] = api_key

    # Buscar escaneos previos
    search_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=3"
    data = safe_get(search_url, headers=headers)

    if not data or "_error" in data or not data.get("results"):
        return {"_no_results": True, "message": "Sin escaneos previos en URLScan"}

    results = data["results"][:1][0]  # más reciente
    page = results.get("page", {})
    stats = results.get("stats", {})
    verdicts = results.get("verdicts", {})
    overall = verdicts.get("overall", {})

    return {
        "scan_id": results.get("_id"),
        "url": page.get("url"),
        "ip": page.get("ip"),
        "country": page.get("country"),
        "server": page.get("server"),
        "asn_name": page.get("asnname"),
        "screenshot": results.get("screenshot"),
        "malicious": overall.get("malicious", False),
        "score": overall.get("score", 0),
        "tags": overall.get("tags", []),
        "requests_total": stats.get("totalRequests", 0),
        "links_total": stats.get("outlinks", 0),
        "scan_time": results.get("task", {}).get("time"),
    }

# ═══════════════════════════════════════════════════════════════════
#  MÓDULO 7: SHODAN
# ═══════════════════════════════════════════════════════════════════

def check_shodan(ip: str, api_key: str) -> dict:
    if not api_key:
        return {"_skip": True, "_reason": "API key no configurada"}
    if not ip:
        return {"_error": "IP no disponible"}

    url = f"https://api.shodan.io/shodan/host/{ip}"
    data = safe_get(url, params={"key": api_key})

    if not data or "_error" in data:
        return {"_error": data.get("_error", "Error") if data else "Sin respuesta"}
    if "error" in data:
        return {"_error": data["error"]}

    ports = data.get("ports", [])
    services = []
    for item in data.get("data", [])[:8]:
        port = item.get("port")
        transport = item.get("transport", "tcp")
        product = item.get("product", "")
        banner = (item.get("data", "") or "")[:80].strip()
        services.append({
            "port": port, "transport": transport,
            "product": product, "banner": banner[:60],
        })

    vulns = list(data.get("vulns", {}).keys()) if data.get("vulns") else []
    tags = data.get("tags", [])

    return {
        "ip": data.get("ip_str"),
        "org": data.get("org"),
        "isp": data.get("isp"),
        "asn": data.get("asn"),
        "country": data.get("country_name"),
        "city": data.get("city"),
        "ports": ports,
        "services": services,
        "vulns": vulns,
        "tags": tags,
        "hostnames": data.get("hostnames", []),
        "os": data.get("os"),
        "last_update": data.get("last_update"),
    }

# ═══════════════════════════════════════════════════════════════════
#  MÓDULO 8: GEOLOCALIZACIÓN (ip-api.com — sin clave)
# ═══════════════════════════════════════════════════════════════════

def geolocate_ip(ip: str) -> dict:
    if not ip:
        return {}
    try:
        # Omitir IPs privadas
        if ipaddress.ip_address(ip).is_private:
            return {"_private": True}
    except Exception:
        pass
    data = safe_get(
        f"http://ip-api.com/json/{ip}",
        params={"fields": "status,country,countryCode,region,city,lat,lon,isp,org,as,hosting"}
    )
    if data and data.get("status") == "success":
        return data
    return {}

# ═══════════════════════════════════════════════════════════════════
#  MÓDULO 9: SSL/TLS
# ═══════════════════════════════════════════════════════════════════

def check_ssl(domain: str) -> dict:
    result = {
        "has_ssl": False, "subject": None, "issuer": None,
        "valid_from": None, "valid_to": None, "days_remaining": None,
        "san": [], "version": None, "expired": False, "self_signed": False,
        "error": None,
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result["has_ssl"] = True
                result["version"] = ssock.version()

                subj = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                result["subject"] = subj.get("commonName", "")
                result["issuer"] = issuer.get("organizationName", "")

                nb = cert.get("notBefore", "")
                na = cert.get("notAfter", "")
                fmt = "%b %d %H:%M:%S %Y %Z"
                try:
                    dt_from = datetime.datetime.strptime(nb, fmt)
                    dt_to = datetime.datetime.strptime(na, fmt)
                    result["valid_from"] = dt_from.strftime("%Y-%m-%d")
                    result["valid_to"] = dt_to.strftime("%Y-%m-%d")
                    remaining = (dt_to - datetime.datetime.utcnow()).days
                    result["days_remaining"] = remaining
                    result["expired"] = remaining < 0
                except Exception:
                    pass

                san_raw = cert.get("subjectAltName", [])
                result["san"] = [v for k, v in san_raw if k == "DNS"]

                # Auto-firmado si subject == issuer
                subj_cn = subj.get("commonName", "")
                issuer_cn = issuer.get("commonName", "")
                result["self_signed"] = (subj_cn == issuer_cn)
    except ssl.SSLError as e:
        result["error"] = f"SSL Error: {str(e)[:100]}"
    except socket.timeout:
        result["error"] = "Timeout al conectar al puerto 443"
    except ConnectionRefusedError:
        result["error"] = "Puerto 443 cerrado"
    except Exception as e:
        result["error"] = str(e)[:120]
    return result

# ═══════════════════════════════════════════════════════════════════
#  MÓDULO 10: RISK SCORE CALCULADO
# ═══════════════════════════════════════════════════════════════════

def calculate_risk_score(
    vt: dict, abuse: dict, whois_data: dict,
    email_sec: dict, ssl_data: dict, urlscan: dict
) -> tuple[int, list]:
    score = 0
    findings = []

    # VirusTotal
    if not vt.get("_skip") and not vt.get("_error"):
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        if mal >= 10:
            score += 40
            findings.append(f"🔴 VirusTotal: {mal} motores lo detectan como MALICIOSO")
        elif mal >= 3:
            score += 25
            findings.append(f"🟠 VirusTotal: {mal} motores lo marcan como malicioso")
        elif mal > 0:
            score += 10
            findings.append(f"🟡 VirusTotal: {mal} detección(es) de baja confianza")
        if sus > 0:
            score += 5
            findings.append(f"🟡 VirusTotal: {sus} motor(es) lo marcan como sospechoso")

    # AbuseIPDB
    if not abuse.get("_skip") and not abuse.get("_error"):
        abuse_score = abuse.get("abuse_score", 0)
        reports = abuse.get("total_reports", 0)
        if abuse_score >= 80:
            score += 30
            findings.append(f"🔴 AbuseIPDB: Score de abuso {abuse_score}% ({reports} reportes)")
        elif abuse_score >= 40:
            score += 15
            findings.append(f"🟠 AbuseIPDB: Score de abuso {abuse_score}%")
        elif abuse_score > 0:
            score += 5
            findings.append(f"🟡 AbuseIPDB: Score de abuso bajo ({abuse_score}%)")

    # Edad del dominio (dominios nuevos son más sospechosos)
    age = whois_data.get("age_days")
    if age is not None:
        if age < 30:
            score += 20
            findings.append(f"🔴 Dominio MUY RECIENTE: solo {age} días de antigüedad")
        elif age < 180:
            score += 10
            findings.append(f"🟠 Dominio reciente: {age} días (~{age//30} meses)")
        elif age < 365:
            score += 5
            findings.append(f"🟡 Dominio con menos de 1 año de antigüedad ({age} días)")

    # Email security
    if not email_sec["spf"]["found"]:
        score += 5
        findings.append("🟡 Sin registro SPF — spoofing de email posible")
    if not email_sec["dmarc"]["found"]:
        score += 5
        findings.append("🟡 Sin registro DMARC — sin política anti-spoofing")
    if email_sec["spf"]["found"] and "+all" in (email_sec["spf"]["record"] or ""):
        score += 10
        findings.append("🔴 SPF con '+all' — permite cualquier remitente (peligroso)")

    # SSL
    if not ssl_data.get("has_ssl"):
        score += 10
        findings.append("🟠 Sin HTTPS/SSL — tráfico sin cifrar")
    elif ssl_data.get("expired"):
        score += 15
        findings.append("🔴 Certificado SSL EXPIRADO")
    elif ssl_data.get("self_signed"):
        score += 10
        findings.append("🟠 Certificado SSL autofirmado (no confiable)")
    elif (ssl_data.get("days_remaining") or 999) < 15:
        score += 5
        findings.append(f"🟡 Certificado SSL por expirar en {ssl_data['days_remaining']} días")

    # URLScan
    if not urlscan.get("_no_results") and urlscan.get("malicious"):
        score += 20
        findings.append("🔴 URLScan.io: marcado como MALICIOSO en último escaneo")

    # WHOIS sin datos
    if whois_data.get("raw_error") and not whois_data.get("created"):
        score += 5
        findings.append("🟡 WHOIS: Información limitada o sin fecha de creación")

    if not findings:
        findings.append("✅ No se detectaron indicadores de compromiso relevantes")

    return min(score, 100), findings

# ═══════════════════════════════════════════════════════════════════
#  RENDER: IMPRESIÓN DEL REPORTE
# ═══════════════════════════════════════════════════════════════════

def render_header(domain: str, timestamp: str):
    console.print()
    console.print(Rule(style="cyan"))
    console.print(
        Align.center(
            Text("🔍  DOMAIN INVESTIGATOR — Reporte OSINT", style="bold cyan")
        )
    )
    console.print(Align.center(Text(f"Dominio analizado: {domain}", style="bold white")))
    console.print(Align.center(Text(f"Timestamp: {timestamp} UTC", style="dim")))
    console.print(Rule(style="cyan"))
    console.print()


def render_risk_summary(score: int, findings: list):
    badge = risk_badge(score)
    t = Table.grid(padding=(0, 2))
    t.add_column(style="bold")
    t.add_column()
    t.add_row("Nivel de Riesgo:", badge)

    panel_content = []
    for f in findings:
        panel_content.append(f)

    console.print(
        Panel(
            "\n".join(panel_content),
            title="[bold yellow]⚠️  RESUMEN DE RIESGO[/bold yellow]",
            subtitle=f"Score total: {score}/100",
            border_style="yellow",
            padding=(1, 2),
        )
    )
    console.print(t)
    console.print()


def render_whois(data: dict):
    t = Table(title="📋 WHOIS — Información del Dominio", box=box.ROUNDED,
              border_style="blue", show_header=True, header_style="bold blue")
    t.add_column("Campo", style="cyan", width=20)
    t.add_column("Valor", style="white")

    age = data.get("age_days")
    if age is not None:
        years = age // 365
        months = (age % 365) // 30
        age_str = f"{age} días"
        if years > 0:
            age_str += f" (~{years} año{'s' if years>1 else ''} {months} mes{'es' if months!=1 else ''})"
        elif months > 0:
            age_str += f" (~{months} mes{'es' if months!=1 else ''})"
        age_style = "red" if age < 30 else "yellow" if age < 365 else "green"
        age_display = Text(age_str, style=f"bold {age_style}")
    else:
        age_display = Text("No disponible", style="dim")

    t.add_row("Registrador", na_if_empty(data.get("registrar")))
    t.add_row("Creado", na_if_empty(data.get("created")))
    t.add_row("Antigüedad", age_display)
    t.add_row("Actualizado", na_if_empty(data.get("updated")))
    t.add_row("Expira", na_if_empty(data.get("expires")))
    t.add_row("País", na_if_empty(data.get("country")))
    status_list = data.get("status", [])
    status_short = [s.split(" ")[0] if isinstance(s, str) else str(s) for s in status_list[:3]]
    t.add_row("Estado", na_if_empty(status_short))
    ns_list = data.get("name_servers", [])
    if ns_list:
        for i, ns in enumerate(ns_list[:4]):
            t.add_row("Name Server" if i == 0 else "", str(ns).lower())
    if data.get("raw_error"):
        t.add_row("⚠️ Error WHOIS", Text(str(data["raw_error"])[:80], style="yellow"))

    console.print(t)
    console.print()


def render_dns(dns_data: dict):
    t = Table(title="🌐 DNS — Registros del Dominio", box=box.ROUNDED,
              border_style="cyan", header_style="bold cyan")
    t.add_column("Tipo", style="bold cyan", width=10)
    t.add_column("Valor(es)", style="white")

    ips = dns_data.get("ips", [])
    ipv6 = dns_data.get("ipv6", [])
    ns = dns_data.get("ns", [])
    mx = dns_data.get("mx", [])

    if ips:
        t.add_row("A (IPv4)", "\n".join(ips))
    else:
        t.add_row("A (IPv4)", Text("Sin registros A", style="red"))
    if ipv6:
        t.add_row("AAAA (IPv6)", "\n".join(ipv6))
    if ns:
        t.add_row("NS", "\n".join(ns))
    if mx:
        t.add_row("MX", "\n".join(mx))
    if dns_data.get("error"):
        t.add_row("❌ Error", str(dns_data["error"])[:80])

    console.print(t)
    console.print()


def render_email_security(data: dict):
    spf = data["spf"]
    dmarc = data["dmarc"]
    dkim = data["dkim"]

    t = Table(title="📧 Seguridad de Email (SPF / DKIM / DMARC)", box=box.ROUNDED,
              border_style="magenta", header_style="bold magenta")
    t.add_column("Protocolo", style="bold", width=12)
    t.add_column("Estado", width=8)
    t.add_column("Detalle", style="white")

    # SPF
    spf_icon = "✅" if spf["found"] else "❌"
    spf_detail = spf.get("policy", "No encontrado")
    if spf.get("record"):
        rec = spf["record"]
        spf_detail += f"\n[dim]{rec[:90]}{'...' if len(rec)>90 else ''}[/dim]"
    t.add_row("SPF", spf_icon, spf_detail if spf["found"] else Text("Registro no encontrado", style="red"))

    # DMARC
    dmarc_icon = "✅" if dmarc["found"] else "❌"
    dmarc_detail = dmarc.get("policy", "No encontrado")
    if dmarc.get("rua"):
        dmarc_detail += f"\n[dim]Reportes a: {dmarc['rua']}[/dim]"
    t.add_row("DMARC", dmarc_icon, dmarc_detail if dmarc["found"] else Text("Registro no encontrado", style="red"))

    # DKIM
    found_sels = dkim.get("selectors_found", [])
    dkim_icon = "✅" if found_sels else "⚠️"
    if found_sels:
        dkim_detail = f"Selectores activos: {', '.join(found_sels)}"
    else:
        dkim_detail = f"Ninguno de {len(dkim['selectors_checked'])} selectores comunes encontrado"
    t.add_row("DKIM", dkim_icon, dkim_detail)

    console.print(t)
    console.print()


def render_ssl(data: dict):
    t = Table(title="🔒 Certificado SSL/TLS", box=box.ROUNDED,
              border_style="green", header_style="bold green")
    t.add_column("Campo", style="bold green", width=20)
    t.add_column("Valor", style="white")

    if data.get("error") and not data.get("has_ssl"):
        t.add_row("Estado", Text(f"❌ Sin SSL — {data['error']}", style="red"))
    else:
        ssl_status = "✅ Activo" if data.get("has_ssl") else "❌ No disponible"
        if data.get("expired"):
            ssl_status = "🔴 EXPIRADO"
        elif data.get("self_signed"):
            ssl_status = "⚠️  Auto-firmado"
        t.add_row("Estado", ssl_status)
        t.add_row("Versión TLS", na_if_empty(data.get("version")))
        t.add_row("Sujeto (CN)", na_if_empty(data.get("subject")))
        t.add_row("Emisor", na_if_empty(data.get("issuer")))
        t.add_row("Válido desde", na_if_empty(data.get("valid_from")))
        t.add_row("Válido hasta", na_if_empty(data.get("valid_to")))

        days = data.get("days_remaining")
        if days is not None:
            color = "red" if days < 0 else "yellow" if days < 30 else "green"
            d_text = f"EXPIRADO hace {abs(days)} días" if days < 0 else f"{days} días restantes"
            t.add_row("Días restantes", Text(d_text, style=f"bold {color}"))

        san = data.get("san", [])
        if san:
            t.add_row("SAN (dominios)", "\n".join(san[:6]) + ("\n..." if len(san) > 6 else ""))

    console.print(t)
    console.print()


def render_virustotal(data: dict, domain: str):
    if data.get("_skip"):
        console.print(Panel(
            f"[yellow]VirusTotal: {data.get('_reason', 'No configurado')}[/yellow]\n"
            f"[dim]Obtén tu API key gratuita en: https://www.virustotal.com/gui/sign-in[/dim]",
            title="[bold red]🛡️  VirusTotal[/bold red]", border_style="red"
        ))
        console.print()
        return

    if data.get("_error"):
        console.print(Panel(f"[red]Error: {data['_error']}[/red]",
                            title="[bold red]🛡️  VirusTotal[/bold red]", border_style="red"))
        console.print()
        return

    mal = data.get("malicious", 0)
    sus = data.get("suspicious", 0)
    harm = data.get("harmless", 0)
    undet = data.get("undetected", 0)
    total = mal + sus + harm + undet

    t = Table(title="🛡️  VirusTotal — Análisis de Motores Antivirus", box=box.ROUNDED,
              border_style="red", header_style="bold red")
    t.add_column("Métrica", style="bold", width=22)
    t.add_column("Resultado", style="white")

    mal_text = Text(f"{mal}/{total} motores", style="bold red" if mal > 0 else "green")
    sus_text = Text(f"{sus}/{total} motores", style="yellow" if sus > 0 else "green")
    t.add_row("🔴 Malicioso", mal_text)
    t.add_row("🟡 Sospechoso", sus_text)
    t.add_row("✅ Limpio", f"{harm} motores")
    t.add_row("⚪ Sin detectar", f"{undet} motores")
    t.add_row("Reputación VT", str(data.get("reputation", 0)))
    t.add_row("Votos maliciosos", str(data.get("votes_malicious", 0)))
    t.add_row("Votos limpios", str(data.get("votes_harmless", 0)))
    if data.get("tags"):
        t.add_row("Etiquetas", ", ".join(data["tags"][:5]))
    if data.get("categories"):
        cats = list(data["categories"].values())[:4]
        t.add_row("Categorías", ", ".join(cats))
    if data.get("last_analysis_date"):
        ts = datetime.datetime.utcfromtimestamp(data["last_analysis_date"])
        t.add_row("Último análisis", ts.strftime("%Y-%m-%d %H:%M UTC"))
    t.add_row("🔗 Enlace VT", f"https://www.virustotal.com/gui/domain/{domain}")

    console.print(t)
    console.print()


def render_abuseipdb(data: dict):
    if data.get("_skip"):
        console.print(Panel(
            f"[yellow]AbuseIPDB: {data.get('_reason', 'No configurado')}[/yellow]\n"
            f"[dim]Obtén tu API key gratuita en: https://www.abuseipdb.com/register[/dim]",
            title="[bold dark_orange]🚨 AbuseIPDB[/bold dark_orange]", border_style="dark_orange"
        ))
        console.print()
        return

    if data.get("_error"):
        console.print(Panel(f"[red]Error: {data['_error']}[/red]",
                            title="[bold dark_orange]🚨 AbuseIPDB[/bold dark_orange]",
                            border_style="dark_orange"))
        console.print()
        return

    t = Table(title="🚨 AbuseIPDB — Reputación de IP", box=box.ROUNDED,
              border_style="dark_orange", header_style="bold dark_orange")
    t.add_column("Campo", style="bold", width=22)
    t.add_column("Valor", style="white")

    abuse_score = data.get("abuse_score", 0)
    color = "red" if abuse_score >= 80 else "yellow" if abuse_score >= 40 else "green"
    score_text = Text(f"{abuse_score}%", style=f"bold {color}")

    t.add_row("IP analizada", na_if_empty(data.get("ip")))
    t.add_row("Score de Abuso", score_text)
    t.add_row("Total reportes (90d)", str(data.get("total_reports", 0)))
    t.add_row("Usuarios distintos", str(data.get("num_distinct_users", 0)))
    t.add_row("ISP / Proveedor", na_if_empty(data.get("isp")))
    t.add_row("País", na_if_empty(data.get("country")))
    t.add_row("Tipo de uso", na_if_empty(data.get("usage_type")))
    t.add_row("En whitelist", "Sí ✅" if data.get("is_whitelisted") else "No")
    if data.get("last_reported"):
        t.add_row("Último reporte", str(data["last_reported"])[:19])

    console.print(t)
    console.print()


def render_geo(data: dict):
    if not data or data.get("_private"):
        return
    t = Table(title="🗺️  Geolocalización de IP", box=box.ROUNDED,
              border_style="blue", header_style="bold blue")
    t.add_column("Campo", style="bold cyan", width=18)
    t.add_column("Valor", style="white")

    t.add_row("País", f"{data.get('country', 'N/A')} ({data.get('countryCode', '')})")
    t.add_row("Región / Ciudad", f"{data.get('region', 'N/A')} / {data.get('city', 'N/A')}")
    t.add_row("Coordenadas", f"{data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")
    t.add_row("ISP", na_if_empty(data.get("isp")))
    t.add_row("Organización", na_if_empty(data.get("org")))
    t.add_row("ASN", na_if_empty(data.get("as")))
    t.add_row("¿Hosting/VPS?", "🚩 Sí" if data.get("hosting") else "No")

    console.print(t)
    console.print()


def render_urlscan(data: dict, domain: str):
    if data.get("_no_results"):
        console.print(Panel(
            f"[dim]{data.get('message', 'Sin resultados')}[/dim]\n"
            f"[dim]Escanea manualmente en: https://urlscan.io/search/#domain:{domain}[/dim]",
            title="[bold purple]🔎 URLScan.io[/bold purple]", border_style="purple"
        ))
        console.print()
        return

    if data.get("_error"):
        console.print(Panel(f"[red]Error: {data['_error']}[/red]",
                            title="[bold purple]🔎 URLScan.io[/bold purple]", border_style="purple"))
        console.print()
        return

    t = Table(title="🔎 URLScan.io — Último escaneo", box=box.ROUNDED,
              border_style="purple", header_style="bold purple")
    t.add_column("Campo", style="bold", width=22)
    t.add_column("Valor", style="white")

    malicious = data.get("malicious", False)
    verdict_text = Text("⚠️ MALICIOSO", style="bold red") if malicious else Text("✅ Limpio", style="green")
    t.add_row("Veredicto", verdict_text)
    t.add_row("Score", str(data.get("score", 0)))
    t.add_row("IP detectada", na_if_empty(data.get("ip")))
    t.add_row("País", na_if_empty(data.get("country")))
    t.add_row("Servidor", na_if_empty(data.get("server")))
    t.add_row("ASN / Org", na_if_empty(data.get("asn_name")))
    t.add_row("Total requests", str(data.get("requests_total", 0)))
    t.add_row("Total outlinks", str(data.get("links_total", 0)))
    if data.get("tags"):
        t.add_row("Tags", ", ".join(data["tags"]))
    if data.get("scan_time"):
        t.add_row("Fecha escaneo", str(data["scan_time"])[:19])
    if data.get("scan_id"):
        t.add_row("🔗 Ver escaneo", f"https://urlscan.io/result/{data['scan_id']}/")

    console.print(t)
    console.print()


def render_shodan(data: dict):
    if data.get("_skip"):
        console.print(Panel(
            f"[yellow]Shodan: {data.get('_reason', 'No configurado')}[/yellow]\n"
            f"[dim]Obtén tu API key en: https://account.shodan.io/[/dim]",
            title="[bold bright_cyan]🔭 Shodan[/bold bright_cyan]", border_style="bright_cyan"
        ))
        console.print()
        return

    if data.get("_error"):
        console.print(Panel(f"[yellow]Shodan: {data['_error']}[/yellow]",
                            title="[bold bright_cyan]🔭 Shodan[/bold bright_cyan]",
                            border_style="bright_cyan"))
        console.print()
        return

    t = Table(title="🔭 Shodan — Puertos y Servicios Expuestos", box=box.ROUNDED,
              border_style="bright_cyan", header_style="bold bright_cyan")
    t.add_column("Campo", style="bold", width=22)
    t.add_column("Valor", style="white")

    t.add_row("Organización", na_if_empty(data.get("org")))
    t.add_row("ISP", na_if_empty(data.get("isp")))
    t.add_row("ASN", na_if_empty(data.get("asn")))
    t.add_row("País / Ciudad", f"{na_if_empty(data.get('country'))} / {na_if_empty(data.get('city'))}")
    t.add_row("OS detectado", na_if_empty(data.get("os")))
    ports = data.get("ports", [])
    t.add_row("Puertos abiertos", ", ".join(str(p) for p in sorted(ports)) if ports else "N/A")

    vulns = data.get("vulns", [])
    if vulns:
        vuln_text = Text(", ".join(vulns[:5]), style="bold red")
        t.add_row("⚠️ CVEs detectados", vuln_text)
    else:
        t.add_row("CVEs detectados", Text("Ninguno detectado ✅", style="green"))

    if data.get("tags"):
        t.add_row("Tags Shodan", ", ".join(data["tags"]))
    if data.get("hostnames"):
        t.add_row("Hostnames", "\n".join(data["hostnames"][:3]))
    if data.get("last_update"):
        t.add_row("Última actualización", str(data["last_update"])[:19])

    console.print(t)
    console.print()

    # Sub-tabla de servicios
    if data.get("services"):
        st = Table(title="Servicios detectados por Shodan", box=box.SIMPLE_HEAD,
                   border_style="bright_cyan", header_style="bold")
        st.add_column("Puerto", style="cyan", width=8)
        st.add_column("Proto", width=6)
        st.add_column("Producto", style="yellow", width=20)
        st.add_column("Banner (extracto)", style="dim", width=45)
        for svc in data["services"]:
            st.add_row(
                str(svc.get("port", "")),
                svc.get("transport", ""),
                svc.get("product", "") or "-",
                svc.get("banner", "") or "-",
            )
        console.print(st)
        console.print()


def render_footer(domain: str):
    console.print(Rule(style="cyan"))
    console.print(
        Panel(
            "[bold]🔗 Recursos adicionales de investigación manual:[/bold]\n\n"
            f"  • VirusTotal:    https://www.virustotal.com/gui/domain/{domain}\n"
            f"  • Shodan:        https://www.shodan.io/search?query={domain}\n"
            f"  • URLScan:       https://urlscan.io/search/#domain:{domain}\n"
            f"  • AbuseIPDB:     https://www.abuseipdb.com/check/{domain}\n"
            f"  • MXToolbox:     https://mxtoolbox.com/SuperTool.aspx?action=spf%3a{domain}\n"
            f"  • WHOIS:         https://whois.domaintools.com/{domain}\n"
            f"  • Google Safe:   https://transparencyreport.google.com/safe-browsing/search?url={domain}\n"
            f"  • ThreatFox:     https://threatfox.abuse.ch/browse.php?search=ioc%3A{domain}\n"
            "  \n[dim]Recuerda: ninguna herramienta es 100% definitiva. Correlaciona los hallazgos.[/dim]",
            title="[dim]Fin del Reporte[/dim]",
            border_style="dim",
        )
    )
    console.print()


# ═══════════════════════════════════════════════════════════════════
#  FUNCIÓN PRINCIPAL
# ═══════════════════════════════════════════════════════════════════

def investigate(domain: str, config: dict, save_json: bool = False):
    domain = domain.lower().strip().removeprefix("http://").removeprefix("https://").split("/")[0]
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    render_header(domain, timestamp)

    results = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:

        def run(desc, fn, *args, key=None):
            task = progress.add_task(desc, total=None)
            r = fn(*args)
            progress.remove_task(task)
            if key:
                results[key] = r
            return r

        # Ejecutar todos los módulos
        dns_data = run("Resolviendo DNS...", resolve_domain, domain, key="dns")
        primary_ip = dns_data.get("ips", [None])[0]

        whois_data = run("Consultando WHOIS...", get_whois, domain, key="whois")
        email_sec = run("Verificando SPF/DKIM/DMARC...", check_email_security, domain, key="email_security")
        ssl_data = run("Inspeccionando certificado SSL...", check_ssl, domain, key="ssl")
        geo_data = run("Geolocalizando IP...", geolocate_ip, primary_ip or "", key="geo")
        vt_data = run("Consultando VirusTotal...", check_virustotal, domain, config["VIRUSTOTAL_API_KEY"], key="virustotal")
        abuse_data = run("Consultando AbuseIPDB...", check_abuseipdb, primary_ip or "", config["ABUSEIPDB_API_KEY"], key="abuseipdb")
        urlscan_data = run("Consultando URLScan.io...", check_urlscan, domain, config["URLSCAN_API_KEY"], key="urlscan")
        shodan_data = run("Consultando Shodan...", check_shodan, primary_ip or "", config["SHODAN_API_KEY"], key="shodan")

    # Calcular riesgo
    score, findings = calculate_risk_score(
        vt_data, abuse_data, whois_data, email_sec, ssl_data, urlscan_data
    )
    results["risk_score"] = score
    results["risk_findings"] = findings

    # ── Renderizar secciones ──────────────────────────────────────
    render_risk_summary(score, findings)
    render_whois(whois_data)
    render_dns(dns_data)
    render_email_security(email_sec)
    render_ssl(ssl_data)
    render_geo(geo_data)
    render_virustotal(vt_data, domain)
    render_abuseipdb(abuse_data)
    render_urlscan(urlscan_data, domain)
    render_shodan(shodan_data)
    render_footer(domain)

    # ── Guardar JSON ──────────────────────────────────────────────
    if save_json:
        output_file = f"report_{domain.replace('.', '_')}_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump({
                "domain": domain,
                "timestamp": timestamp,
                "risk_score": score,
                "risk_findings": findings,
                "results": {k: v for k, v in results.items() if k not in ("risk_score", "risk_findings")},
            }, f, indent=2, default=str)
        console.print(f"\n[green]✅ Reporte JSON guardado en:[/green] [bold]{output_file}[/bold]\n")


# ═══════════════════════════════════════════════════════════════════
#  ENTRYPOINT
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Domain Investigator — Herramienta OSINT para análisis de dominios",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python domain_investigator.py example.com
  python domain_investigator.py suspicious-domain.xyz --json
  python domain_investigator.py phishing-site.net --vt-key TU_CLAVE --abuse-key TU_CLAVE

APIs requeridas (gratuitas):
  VirusTotal  → https://www.virustotal.com/gui/sign-in
  AbuseIPDB   → https://www.abuseipdb.com/register
  URLScan.io  → https://urlscan.io/user/signup  (opcional, funciona sin clave)
  Shodan      → https://account.shodan.io/register
        """,
    )
    parser.add_argument("domain", help="Dominio a investigar (ej: example.com)")
    parser.add_argument("--json", action="store_true", help="Guardar resultado en JSON")
    parser.add_argument("--vt-key", help="API Key de VirusTotal", default="")
    parser.add_argument("--abuse-key", help="API Key de AbuseIPDB", default="")
    parser.add_argument("--urlscan-key", help="API Key de URLScan.io", default="")
    parser.add_argument("--shodan-key", help="API Key de Shodan", default="")

    args = parser.parse_args()
    config = load_config()

    # Claves por argumento tienen prioridad sobre config.ini
    if args.vt_key:      config["VIRUSTOTAL_API_KEY"] = args.vt_key
    if args.abuse_key:   config["ABUSEIPDB_API_KEY"] = args.abuse_key
    if args.urlscan_key: config["URLSCAN_API_KEY"] = args.urlscan_key
    if args.shodan_key:  config["SHODAN_API_KEY"] = args.shodan_key

    investigate(args.domain, config, save_json=args.json)


if __name__ == "__main__":
    main()
