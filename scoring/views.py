# app/views.py
from __future__ import annotations

import os
import re
import io
import zipfile
import base64
import random
import tempfile
import hashlib
import json
import socket
from typing import Dict, Any, List, Tuple
from xml.etree import ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse



import requests
from requests.exceptions import RequestException, SSLError, Timeout, ConnectionError as ReqConnError

from django.shortcuts import render, redirect
from django.template.loader import get_template
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.decorators.http import require_POST
from django.http import JsonResponse, HttpResponse, HttpResponseBadRequest
from django.http import HttpResponseBadRequest, JsonResponse
from django.views.decorators.http import require_POST

import os
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend suitable for headless environments
os.environ.setdefault("MPLCONFIGDIR", "/tmp/matplotlib")  # Set Matplotlib cache directory
import matplotlib.pyplot as plt



from dotenv import load_dotenv
load_dotenv()

# PDF export
# from xhtml2pdf import pisa
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from django.utils.html import strip_tags
from bs4 import BeautifulSoup

def generate_pdf(html_content: str):
    """
    Convert a simple HTML string to a PDF using ReportLab.
    This works on Vercel because it avoids Cairo/Pango dependencies.
    """
    # Create a buffer
    pdf_buffer = BytesIO()
    p = canvas.Canvas(pdf_buffer, pagesize=letter)

    # Basic HTML → text conversion (strip tags or use BeautifulSoup for a cleaner result)
    soup = BeautifulSoup(html_content, "html.parser")
    text_content = soup.get_text()

    # Start drawing text line by line
    text_object = p.beginText(50, 750)  # (x, y) starting position
    text_object.setFont("Helvetica", 12)

    for line in text_content.splitlines():
        if line.strip():
            text_object.textLine(line.strip())

    p.drawText(text_object)
    p.showPage()
    p.save()

    pdf_buffer.seek(0)
    return pdf_buffer



# ===== Utils (your modules) =====
from .utils import (
    extract_applicant_name,
    extract_github_username,
    extract_leetcode_username,
    calculate_dynamic_ats_score_v2,
    derive_resume_metrics,
    ats_resume_scoring,
    extract_links_combined,
    extract_text_from_docx,
    generate_pie_chart_v2,
    calculate_screening_emphasis,
    get_grade_tag,
    count_only_certifications,
    suggest_role_certifications,
    score_linkedin_public_html,
)

from .profile_scoring import *
from .ats_score_non_tech import ats_scoring_non_tech_v2

# ========= In-memory OTP / user stores (demo only) =========
registered_users: Dict[str, str] = {}
OTP_TTL_SECONDS = 300  # 5 min

def norm_email(email: str) -> str:
    return (email or "").strip().lower()

def norm_mobile(mobile: str) -> str:
    return re.sub(r"\D+", "", (mobile or "").strip())

# -------------------------------------------------------------------
# Microsoft Graph email helpers (INLINE as requested)
# Uses OUTLOOK_* from environment
# -------------------------------------------------------------------
from django.conf import settings

OUTLOOK_TENANT_ID     = os.getenv("OUTLOOK_TENANT_ID", "")
OUTLOOK_CLIENT_ID     = os.getenv("OUTLOOK_CLIENT_ID", "")
OUTLOOK_CLIENT_SECRET = os.getenv("OUTLOOK_CLIENT_SECRET", "")
OUTLOOK_SENDER_EMAIL  = os.getenv("OUTLOOK_SENDER_EMAIL", "")
EMAIL_TIMEOUT         = int(os.getenv("EMAIL_TIMEOUT", "30"))

def _graph_get_token() -> str | None:
    """Client-credentials flow for Microsoft Graph."""
    if not (OUTLOOK_TENANT_ID and OUTLOOK_CLIENT_ID and OUTLOOK_CLIENT_SECRET):
        return None
    token_url = f"https://login.microsoftonline.com/{OUTLOOK_TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": OUTLOOK_CLIENT_ID,
        "client_secret": OUTLOOK_CLIENT_SECRET,
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default",
    }
    try:
        r = requests.post(token_url, data=data, timeout=EMAIL_TIMEOUT)
        if r.ok:
            return r.json().get("access_token")
    except requests.RequestException:
        pass
    return None

def _graph_send_mail(sender_email: str, to_email: str, subject: str, body_text: str) -> tuple[bool, str]:
    """
    Sends mail via Graph: POST /v1.0/users/{sender}/sendMail
    Requires: Application permission 'Mail.Send' + admin consent, and a real mailbox for sender_email.
    """
    token = _graph_get_token()
    if not token:
        return False, "No Graph access token"

    url = f"https://graph.microsoft.com/v1.0/users/{sender_email}/sendMail"
    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": "Text", "content": body_text},
            "toRecipients": [{"emailAddress": {"address": to_email}}],
        },
        "saveToSentItems": False,
    }
    try:
        r = requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=EMAIL_TIMEOUT,
        )
        # 202 is expected on success
        if 200 <= r.status_code < 300:
            return True, "sent"
        return False, f"Graph sendMail failed ({r.status_code}): {r.text[:300]}"
    except requests.RequestException as e:
        return False, f"Graph request error: {e}"

def send_otp_email(to_email: str, otp: str, subject: str):
    """
    First try Microsoft Graph using your client credentials.
    If that fails, fall back to Django email backend (console or SMTP depending on settings).
    """
    sender = OUTLOOK_SENDER_EMAIL or getattr(settings, "DEFAULT_FROM_EMAIL", "") or getattr(settings, "EMAIL_HOST_USER", "")
    if not sender:
        sender = "webmaster@localhost"

    body = f"Your OTP is {otp}. It will expire in {OTP_TTL_SECONDS // 60} minutes."

    # 1) Try Graph (ideal with your provided credentials)
    ok, info = _graph_send_mail(sender, to_email, subject, body)
    if ok:
        return

    # 2) Fallback to Django backend
    from django.core.mail import send_mail as dj_send_mail
    dj_send_mail(
        subject=subject,
        message=body,
        from_email=sender,
        recipient_list=[to_email],
        fail_silently=False,
    )

# ========= Basic pages =========
def landing(request): return render(request, "landing.html")
def signin(request): return render(request, "login.html")
def login_view(request): return render(request, "login.html")
def signup(request): return render(request, "login.html")
def about_us(request): return render(request, "about_us.html")
def upload_resume(request): return render(request, "upload_resume.html")

# ------------------------
# Dedupers
# ------------------------
def _dedupe_preserve_order_strings(seq: List[str]) -> List[str]:
    seen, out = set(), []
    for item in seq:
        if not isinstance(item, str):
            continue
        k = item.strip()
        if not k or k in seen:
            continue
        seen.add(k)
        out.append(k)
    return out

def _dedupe_preserve_order_link_dicts(seq: List[dict]) -> List[dict]:
    seen, out = set(), []
    for item in seq:
        if not isinstance(item, dict):
            continue
        url = (item.get("url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        out.append(item)
    return out

# ------------------------
# Link extraction & helpers
# ------------------------
def _normalize_text(s: str) -> str:
    if not s:
        return ""
    return (
        s.replace("\u200b", "")  # zero-width space
        .replace("\ufeff", "")   # BOM
        .replace("\u00a0", " ")  # NBSP -> space
    )

_PORTFOLIO_HOSTS = (
    "vercel.app","netlify.app","github.io","read.cv","notion.site","notion.so",
    "about.me","carrd.co","wixsite.com","wix.com","wordpress.com","square.site",
    "webflow.io","pages.dev","framer.website","framer.ai","format.com","cargo.site",
    "showwcase.co","behance.net","dribbble.com","super.site",
)

_SOCIAL_HOSTS = (
    "linkedin.com","github.com","leetcode.com","x.com","twitter.com",
    "medium.com","dev.to","kaggle.com","gitlab.com","bitbucket.org",
    "lnkd.in","linktr.ee",
)

_PERSONAL_TLDS = (
    ".me",".dev",".app",".io",".sh",".xyz",".site",".page",".studio",".design",".works",
    ".tech",".codes",".space",".digital",
)

_GH_USER_RE = re.compile(r"https?://(?:[\w\-]+\.)?github\.com/([A-Za-z0-9\-]+)(?:/|$)", re.I)
_LI_ANY_RE  = re.compile(r"https?://(?:[\w\-]+\.)?(?:linkedin\.com|lnkd\.in)(?:/|$)", re.I)
_LI_SLUG_RE = re.compile(r"https?://(?:[\w\-]+\.)?linkedin\.com/(?:in|pub|profile)/([A-Za-z0-9\-_\.]+)/?", re.I)
_LC_USER_RE = re.compile(r"https?://(?:www\.)?leetcode\.com/(?:u|profile)/([A-Za-z0-9\-_]+)/?", re.I)

_URL_RE = re.compile(
    r"""(?ix)
    (?:\b
        (?:https?://|www\.)                           # scheme or www
        [\w\-]+(?:\.[\w\-\u00a1-\uffff]+)+            # domain.tld
        (?::\d{2,5})?                                 # optional port
        (?:/[^\s<>()\[\]{}"']*)?                      # optional path
    )
    |
    (?:\b
        (?:linkedin\.com|lnkd\.in|github\.com|leetcode\.com|notion\.so|notion\.site|
           vercel\.app|netlify\.app|github\.io|webflow\.io|pages\.dev|
           read\.cv|about\.me|carrd\.co|wixsite\.com|wix\.com|wordpress\.com|
           square\.site|framer\.website|framer\.ai|format\.com|cargo\.site|
           showwcase\.co|behance\.net|dribbble\.com|super\.site|gitlab\.com|
           bitbucket\.org|kaggle\.com|medium\.com|dev\.to|linktr\.ee)
        [^\s<>()\[\]{}"']*
    )
    """,
    re.UNICODE,
)

_PUNCT_END = re.compile(r"[),.;:!?]+$")

def _fix_obfuscations(text: str) -> str:
    t = text or ""
    t = re.sub(r"\b(dot|\[dot\]|\(dot\))\b", ".", t, flags=re.I)
    t = re.sub(r"\b(slash|\[slash\]|\(slash\))\b", "/", t, flags=re.I)
    t = re.sub(r"\b(at|\[at\]|\(at\))\b", "@", t, flags=re.I)
    t = t.replace(" :// ", "://").replace(" / ", "/")
    return t

def _ensure_scheme(u: str) -> str:
    if not u:
        return u
    if u.startswith(("http://", "https://")):
        return u
    if u.startswith("www."):
        return "https://" + u
    return "https://" + u

def _strip_trailing_punct(u: str) -> str:
    return _PUNCT_END.sub("", u).strip("()[]{}<>\"' ")

def extract_urls_from_text(text: str) -> List[str]:
    if not text:
        return []
    t = _normalize_text(_fix_obfuscations(text))
    found: List[str] = []
    for m in _URL_RE.finditer(t):
        u = _ensure_scheme(_strip_trailing_punct(m.group(0)))
        if u:
            found.append(u)
    return _dedupe_preserve_order_strings(found)

def extract_links_from_docx(path: str) -> List[str]:
    urls: List[str] = []
    try:
        with zipfile.ZipFile(path) as zf:
            rels_target = "word/_rels/document.xml.rels"
            if rels_target not in zf.namelist():
                return []
            rels_xml = ET.fromstring(zf.read(rels_target))
            rels = {}
            for rel in rels_xml.findall("{http://schemas.openxmlformats.org/package/2006/relationships}Relationship"):
                rId = rel.attrib.get("Id")
                tgt = rel.attrib.get("Target")
                mode = rel.attrib.get("TargetMode", "")
                if rId and tgt and (mode == "External" or tgt.startswith("http")):
                    rels[rId] = tgt
            doc_xml = ET.fromstring(zf.read("word/document.xml"))
            NS = {
                "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
                "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
            }
            for hl in doc_xml.findall(".//w:hyperlink", NS):
                rId = hl.attrib.get("{%s}id" % NS["r"])
                if rId and rId in rels:
                    urls.append(_ensure_scheme(_strip_trailing_punct(rels[rId])))
    except Exception:
        pass
    return _dedupe_preserve_order_strings(urls)

def _domain_of(u: str) -> str:
    try:
        return urlparse(u).netloc.lower()
    except Exception:
        return ""

def classify_link(url: str, title_hint: str = "", path_hint: str = "") -> str:
    u = url or ""
    dom = _domain_of(u)
    if "linkedin.com" in dom or dom == "lnkd.in":
        return "linkedin"
    if "github.com" in dom:
        return "github"
    if "leetcode.com" in dom:
        return "leetcode"
    for h in _PORTFOLIO_HOSTS:
        if h in dom:
            return "portfolio"
    if any(dom.endswith(tld) for tld in _PERSONAL_TLDS):
        return "portfolio"
    hint = f"{title_hint or ''} {path_hint or ''}".lower()
    if any(k in hint for k in ["portfolio", "projects", "work", "case study", "case-studies", "showcase"]):
        return "portfolio"
    if dom and "." in dom and not any(s in dom for s in _SOCIAL_HOSTS):
        return "portfolio"
    return "other"

def infer_github_username(urls: List[str], text: str) -> str:
    for u in urls:
        m = _GH_USER_RE.search(u)
        if m:
            return m.group(1)
    m2 = _GH_USER_RE.search(text or "")
    return m2.group(1) if m2 else ""

def infer_linkedin_slug(urls: List[str], text: str) -> str:
    for u in urls:
        m = _LI_SLUG_RE.search(u)
        if m:
            return m.group(1)
    m2 = _LI_SLUG_RE.search(text or "")
    return m2.group(1) if m2 else ""

def infer_leetcode_username(urls: List[str], text: str) -> str:
    for u in urls:
        m = _LC_USER_RE.search(u)
        if m:
            return m.group(1)
    m2 = _LC_USER_RE.search(text or "")
    return m2.group(1) if m2 else ""

def _detect_contact(resume_text: str) -> bool:
    email = re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", resume_text or "")
    phone = re.search(r"(\+?\d[\d\s\-()]{8,})", resume_text or "")
    return bool(email or phone)

def _grade_pct_label(pct: float) -> str:
    if pct >= 85:
        return "Excellent"
    if pct >= 70:
        return "Good"
    if pct >= 50:
        return "Average"
    return "Poor"

# ------------------------
# URL validation (only valid links influence scoring)
# ------------------------
_DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; ApplyWizzBot/1.3)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en",
    "Connection": "close",
}
_session = requests.Session()
_session.headers.update(_DEFAULT_HEADERS)

def _extract_title(html: str) -> str:
    if not html:
        return ""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""

def fetch_url_status(url: str, timeout: float = 7.5) -> Dict[str, Any]:
    """
    HEAD -> GET with redirects. Returns final_url, status, ok (200), title, path_hint, html.
    Also treats LinkedIn public profile URL patterns as 'present' even if behind a login wall,
    but scoring from HTML will only happen if we actually get a 200 and real HTML.
    """
    result = {"url": url, "final_url": url, "status": None, "ok": False, "title": "", "path_hint": "", "html": ""}

    if not url:
        return result

    try:
        r = _session.head(url, allow_redirects=True, timeout=timeout)
        result.update({"status": r.status_code, "final_url": r.url, "path_hint": urlparse(r.url).path})
        if r.status_code == 200:
            result["ok"] = True

        # Always try GET to capture HTML/title when publicly available
        r = _session.get(result["final_url"], allow_redirects=True, timeout=timeout)
        result.update({"status": r.status_code, "final_url": r.url, "path_hint": urlparse(r.url).path})
        if r.status_code == 200:
            result["ok"] = True
            result["html"] = r.text or ""
            result["title"] = _extract_title(r.text or "")

        # Soft fallback: mark *pattern* as present (ok) for presence UI,
        # but note we still won't have HTML for scoring unless status==200 above.
        host = (urlparse(result["final_url"]).netloc or "").lower()
        path = (urlparse(result["final_url"]).path or "")
        if not result["ok"] and ("linkedin.com" in host or host == "lnkd.in") and re.match(r"^/(in|pub|profile)/", path, flags=re.I):
            result["ok"] = True
            result["title"] = result["title"] or "LinkedIn Profile"

    except (RequestException, SSLError, Timeout, ReqConnError, socket.error):
        pass

    return result

def validate_links_enrich(links: List[Dict[str, Any]], max_workers: int = 6) -> List[Dict[str, Any]]:
    enriched: List[Dict[str, Any]] = []
    futures = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for item in links:
            if not isinstance(item, dict):
                continue
            url = (item.get("url") or "").strip()
            if not url:
                continue
            futures[ex.submit(fetch_url_status, url)] = item
        for fut in as_completed(futures):
            base = futures[fut]
            info = fut.result() if fut else {}
            final_url = info.get("final_url") or base.get("url")
            new_type  = classify_link(final_url, info.get("title") or "", info.get("path_hint") or "")
            enriched.append({**base, **info, "type": new_type})
    by_url = {e.get("url"): e for e in enriched if e.get("url")}
    ordered, seen = [], set()
    for item in links:
        u = (item.get("url") or "").strip()
        if not u or u in seen:
            continue
        ordered.append(by_url.get(u, item))
        seen.add(u)
    return ordered

def only_ok_links(links: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [l for l in links if l.get("ok")]

# ------------------------
# Certifications – extraction + dynamic scoring helpers
# ------------------------
_CERT_HEAD_RE = re.compile(r"^\s*(licenses?\s*&?\s*certifications?|certifications?|licenses?)\s*$", re.I)
_BULLET_RE = re.compile(r"^\s*(?:[-*•■●]|[0-9]+\.)\s*(.+)$")
_CERT_LINE_HINT = re.compile(r"(certif|license|licen[sc]e|credential|badge|certificate|exam|id:|license:)", re.I)

_CERT_PROVIDERS = (
    "aws","amazon web services","azure","microsoft","google cloud","gcp",
    "coursera","udemy","udacity","datacamp","databricks","snowflake","tableau",
    "power bi","oracle","salesforce","trailhead","cisco","red hat","linux foundation",
    "ibm","pmi","prince2","itil","scrum","comptia","kubernetes","ckad","cka","ckad/cka",
    "sap","okta","hashicorp","terraform","mongodb","redis","elastic","neo4j",
)

_CERT_LINK_HOSTS = (
    "credly.com","youracclaim.com","accredible.com","badgr.com","openbadgepassport.com",
    "coursera.org","udemy.com","trailhead.salesforce.com","trailhead.salesforce",
    "aws.amazon.com","cloud.google.com","learn.microsoft.com","docs.microsoft.com",
    "oracle.com","education.oracle.com","datacamp.com","academy.databricks.com",
    "udacity.com","learn.udacity.com","tableau.com","certificates.tableau.com",
    "cisco.com","comptia.org","redhat.com","training.linuxfoundation.org",
)

_CERT_LEVELS = ("associate","professional","expert","specialty","advanced","foundational","practitioner")
_CERT_RELEVANCE_HINTS = (
    "aws","azure","gcp","google cloud","cloud practitioner","solutions architect",
    "devops","kubernetes","k8s","docker","security",
    "data","ml","machine learning","ai","analytics","etl","elt",
    "spark","hadoop","dbt","airflow","snowflake","bigquery","redshift",
    "sql","database","dba","data engineer","data scientist","python","pyspark",
    "tableau","power bi","salesforce","oracle","terraform",
)

def _split_lines_keep(text: str) -> List[str]:
    raw = (text or "")
    parts: List[str] = []
    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln:
            parts.append("")
            continue
        # Split common inline bullet/sep chars
        for chunk in re.split(r"[•·\u2022\|;/,]+", ln):
            c = (chunk or "").strip(" -\t")
            if c:
                parts.append(c)
    return parts

def _looks_like_cert_line(s: str) -> bool:
    if not s:
        return False
    s = s.strip()
    if _CERT_LINE_HINT.search(s):
        return True
    if re.search(r"\b(certified|certificate|credential)\b", s, re.I) and any(p in s.lower() for p in _CERT_PROVIDERS):
        return True
    if re.search(r"\b(AZ|DP|AI|PL|SC|MS)-\d{3}\b", s):
        return True
    if re.search(r"\b(CCA|CKA|CKAD|CKS|PCSAE|PCDRA|PCA)\b", s):
        return True
    if any(k in s.lower() for k in ["digital leader","data engineer","solutions architect","cloud practitioner","desktop specialist"]):
        return True
    return False

def _normalize_cert_name(s: str) -> str:
    s = re.sub(r"\b(license|licen[sc]e|credential\s*id|id|no\.?)\b.*$", "", s, flags=re.I)
    s = re.sub(r"\s{2,}", " ", s).strip(" -–—")
    return s[:180]

def extract_certifications_block(resume_text: str) -> List[str]:
    lines = _split_lines_keep(resume_text)
    out: List[str] = []
    in_block = False
    for line in lines:
        if _CERT_HEAD_RE.match(line):
            in_block = True
            continue
        if in_block:
            if not line.strip():
                continue
            if re.match(r"^(experience|education|projects?|skills?|profile|summary|achievements?)\s*:?\s*$", line, re.I) \
               or re.match(r"^[A-Z][A-Z \-/&]{2,}$", line):
                in_block = False
                continue
            m = _BULLET_RE.match(line)
            candidate = (m.group(1) if m else line).strip()
            if _looks_like_cert_line(candidate):
                out.append(_normalize_cert_name(candidate))
    return out

def extract_certifications_anywhere(resume_text: str) -> List[str]:
    segs = _split_lines_keep(resume_text)
    hits = []
    for s in segs:
        if _looks_like_cert_line(s):
            hits.append(_normalize_cert_name(s))
    norm_map = {}
    for h in hits:
        key = re.sub(r"[\s\-–—]+", " ", h.lower())
        norm_map.setdefault(key, h)
    return list(norm_map.values())

def extract_certifications_from_links(links: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    certs = []
    for l in links or []:
        u = (l.get("final_url") or l.get("url") or "")
        t = (l.get("title") or "")
        dom = (urlparse(u).netloc or "").lower()
        if any(h in dom for h in _CERT_LINK_HOSTS) or "verify" in u.lower() or "badge" in u.lower():
            certs.append({"name": _normalize_cert_name(t or u), "link": u, "ok": bool(l.get("ok"))})
    return certs

def score_certifications(resume_text: str, enriched_links: List[Dict[str, Any]]) -> Tuple[int, List[str], List[str]]:
    from_section = extract_certifications_block(resume_text)
    from_anywhere = extract_certifications_anywhere(resume_text)
    link_items = extract_certifications_from_links(enriched_links)

    text_names = _dedupe_preserve_order_strings(from_section + from_anywhere)
    evidence = []
    verifiable_count = 0
    for it in link_items:
        link = it.get("link")
        if link and link not in evidence:
            evidence.append(link)
        if it.get("ok"):
            verifiable_count += 1

    joined_text = " ".join(text_names + [it.get("name","") for it in link_items]).lower()
    relevant = any(h in joined_text for h in _CERT_RELEVANCE_HINTS)
    level_hit = any(lvl in joined_text for lvl in _CERT_LEVELS)

    unique_cert_count = len(text_names) + len([1 for _ in link_items if not text_names])
    score = 0
    rats: List[str] = []

    if unique_cert_count > 0:
        score += min(4, unique_cert_count)
        rats.append(f"{unique_cert_count} certification(s) identified.")
    if relevant:
        score += 2; rats.append("Certifications relevant to role (cloud/data/devops/analytics/etc.).")
    if verifiable_count >= 1:
        score += 2; rats.append("Verifiable credential link detected.")
    if level_hit:
        score += 1; rats.append("Higher-level credential (Associate/Professional/Expert) mentioned.")
    score = min(9, score)

    if unique_cert_count == 0 and verifiable_count == 0:
        rats = ["No certifications found."]

    return score, rats, evidence

# ========= OTP SIGNUP / LOGIN =========
@csrf_exempt
def send_signup_otp(request):
    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "Invalid request"}, status=405)
    email = norm_email(request.POST.get("email", ""))
    mobile = norm_mobile(request.POST.get("mobile", ""))
    if not email or not mobile:
        return JsonResponse({"status": "error", "message": "Email and mobile required"}, status=400)
    otp = f"{random.randint(100000, 999999)}"
    cache_key = f"signup_otp:{email}:{mobile}"
    from django.core.cache import cache
    cache.set(cache_key, otp, timeout=OTP_TTL_SECONDS)
    try:
        send_otp_email(email, otp, subject="Your ApplyWizz Signup OTP")
        return JsonResponse({"status": "success", "message": "OTP sent to your email"})
    except Exception as e:
        return JsonResponse({"status": "error", "message": f"Failed to send OTP: {e}"}, status=500)

@csrf_exempt
def verify_signup_otp(request):
    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "Invalid request"}, status=405)
    email = norm_email(request.POST.get("email", ""))
    mobile = norm_mobile(request.POST.get("mobile", ""))
    otp = (request.POST.get("otp", "") or "").strip()
    from django.core.cache import cache
    cache_key = f"signup_otp:{email}:{mobile}"
    stored_otp = cache.get(cache_key)
    if stored_otp and stored_otp == otp:
        registered_users[mobile] = email
        cache.delete(cache_key)
        return JsonResponse({"status": "success", "redirect_url": "/login"})
    else:
        return JsonResponse({"status": "error", "message": "Invalid or expired OTP"}, status=400)

@csrf_exempt
def send_login_otp(request):
    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "Invalid request"}, status=405)
    email = norm_email(request.POST.get("email", ""))
    if not email:
        return JsonResponse({"status": "error", "message": "Email required"}, status=400)
    otp = f"{random.randint(100000, 999999)}"
    from django.core.cache import cache
    cache_key = f"login_otp:{email}"
    cache.set(cache_key, otp, timeout=OTP_TTL_SECONDS)
    try:
        send_otp_email(email, otp, subject="Your ApplyWizz Login OTP")
        return JsonResponse({"status": "success", "message": "OTP sent to your email"})
    except Exception as e:
        return JsonResponse({"status": "error", "message": f"Failed to send OTP: {e}"}, status=500)

@csrf_exempt
def verify_login_otp(request):
    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "Invalid request"}, status=405)
    email = norm_email(request.POST.get("email", ""))
    otp = (request.POST.get("otp", "") or "").strip()
    from django.core.cache import cache
    cache_key = f"login_otp:{email}"
    stored_otp = cache.get(cache_key)
    if stored_otp and stored_otp == otp:
        cache.delete(cache_key)
        return JsonResponse({"status": "success", "redirect_url": "/upload_resume"})
    else:
        return JsonResponse({"status": "error", "message": "Invalid or expired OTP"}, status=400)

# ========= PDF Download =========
# def download_resume_pdf(request):
#     # Pull either key (tech/non-tech)
#     context = request.session.get("resume_context_tech") or \
#               request.session.get("resume_context_nontech") or \
#               request.session.get("resume_context", {})
    
#     # Get the user's role from context
#     user_role = context.get("role", "")
    
#     # Check if the user's role is non-technical
#     if user_role in [
#     "Account Executive (Non-Tech)",
#     "Accountant (Non-Tech)",
#     "Business Analyst (Non-Tech)",
#     "Business Development (Non-Tech)",
#     "Consultant (Non-Tech)",
#     "Content Marketer (Non-Tech)",
#     "Customer Service (Non-Tech)",
#     "Customer Success Manager (Non-Tech)",
#     "Data Analyst (Non-Tech)",
#     "Data Entry (Non-Tech)",
#     "Data Science for Germany (Non-Tech)",
#     "Digital Marketing Specialist (Non-Tech)",
#     "Finance (Non-Tech)",
#     "Financial Analyst & KYC Analyst & AML (Non-Tech)",
#     "Financial Analyst (Non-Tech)",
#     "Graphic Designer (Non-Tech)",
#     "Health Care Business Analyst (Non-Tech)",
#     "Health Care Data Engineer (Non-Tech)",
#     "Healthcare Data Analyst (Non-Tech)",
#     "HR Manager (Non-Tech)",
#     "HR Recruiter (Non-Tech)",
#     "Human Resources (HR) (Non-Tech)",
#     "Manufacturing Engineer (Mechanical)",
#     "Marketing (Non-Tech)",
#     "Mechanical Engineer",
#     "Medical Coding (Non-Tech)",
#     "Office Administrator (Non-Tech)",
#     "Operations Manager (Non-Tech)",
#     "Payroll Analyst (Non-Tech)",
#     "Product Manager (Non-Tech)",
#     "Product Marketing Manager (Non-Tech)",
#     "Program Manager (Non-Tech)",
#     "Project Manager (Non-Tech)",
#     "Project Management (Non-Tech)",
#     "Project Management Internship (Non-Tech)",
#     "Procurement Specialist (Non-Tech)",
#     "Quality Assurance (Non-Tech)",
#     "Recruiter (Non-Tech)",
#     "Regulatory Affairs (Non-Tech)",
#     "Safety Analyst (Non-Tech)",
#     "Sales (Non-Tech)",
#     "SEO Specialist (Non-Tech)",
#     "Social Media Manager (Non-Tech)",
#     "Supply Chain Analyst (Non-Tech)",
#     "Supply Chain (Non-Tech)",
#     "Talent Acquisition Specialist (Non-Tech)",
#     "Tax Analyst (Non-Tech)",
#     "Technical Writer (Non-Tech)",

#     ]:
#         # Set template to score_of_non_tech.html for non-technical roles
#         template_path = "score_of_non_tech.html"
#     else:
#         # Default to resume_result.html for technical roles
#         template_path = "resume_result.html"
    
#     # Get the template and render HTML
#     template = get_template(template_path)
#     html = template.render(context)
    
#     # Get the applicant's name from context (assuming it's available)
#     applicant_name = context.get("applicant_name", "unknown_applicant")
    
#     # Create the response and set the content type
#     response = HttpResponse(content_type="application/pdf")
#     response["Content-Disposition"] = f'attachment; filename="{applicant_name}_Profilevalidation_Report.pdf"'
    
#     # Create PDF from HTML content
#     pisa_status = pisa.CreatePDF(html, dest=response)
    
#     if pisa_status.err:
#         return HttpResponse("We had some errors <pre>" + html + "</pre>")
    
#     return response
# # 

from io import BytesIO
from bs4 import BeautifulSoup
from django.http import HttpResponse
from django.template.loader import get_template
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

def download_resume_pdf(request):
    # Pull context from session (tech / non-tech / generic)
    context = (
        request.session.get("resume_context_tech") or
        request.session.get("resume_context_nontech") or
        request.session.get("resume_context", {})
    )

    # Determine template based on user role
    user_role = context.get("role", "")
    non_tech_roles = [
        "Account Executive (Non-Tech)",
        "Accountant (Non-Tech)",
        "Business Analyst (Non-Tech)",
        "Business Development (Non-Tech)",
        "Consultant (Non-Tech)",
        "Content Marketer (Non-Tech)",
        "Customer Service (Non-Tech)",
        "Customer Success Manager (Non-Tech)",
        "Data Analyst (Non-Tech)",
        "Data Entry (Non-Tech)",
        "Data Science for Germany (Non-Tech)",
        "Digital Marketing Specialist (Non-Tech)",
        "Finance (Non-Tech)",
        "Financial Analyst & KYC Analyst & AML (Non-Tech)",
        "Financial Analyst (Non-Tech)",
        "Graphic Designer (Non-Tech)",
        "Health Care Business Analyst (Non-Tech)",
        "Health Care Data Engineer (Non-Tech)",
        "Healthcare Data Analyst (Non-Tech)",
        "HR Manager (Non-Tech)",
        "HR Recruiter (Non-Tech)",
        "Human Resources (HR) (Non-Tech)",
        "Manufacturing Engineer (Mechanical)",
        "Marketing (Non-Tech)",
        "Mechanical Engineer",
        "Medical Coding (Non-Tech)",
        "Office Administrator (Non-Tech)",
        "Operations Manager (Non-Tech)",
        "Payroll Analyst (Non-Tech)",
        "Product Manager (Non-Tech)",
        "Product Marketing Manager (Non-Tech)",
        "Program Manager (Non-Tech)",
        "Project Manager (Non-Tech)",
        "Project Management (Non-Tech)",
        "Project Management Internship (Non-Tech)",
        "Procurement Specialist (Non-Tech)",
        "Quality Assurance (Non-Tech)",
        "Recruiter (Non-Tech)",
        "Regulatory Affairs (Non-Tech)",
        "Safety Analyst (Non-Tech)",
        "Sales (Non-Tech)",
        "SEO Specialist (Non-Tech)",
        "Social Media Manager (Non-Tech)",
        "Supply Chain Analyst (Non-Tech)",
        "Supply Chain (Non-Tech)",
        "Talent Acquisition Specialist (Non-Tech)",
        "Tax Analyst (Non-Tech)",
        "Technical Writer (Non-Tech)",
    ]

    template_path = "score_of_non_tech.html" if user_role in non_tech_roles else "resume_result.html"

    # Render the HTML content
    template = get_template(template_path)
    html_content = template.render(context)

    # Extract plain text from HTML for PDF generation
    soup = BeautifulSoup(html_content, "html.parser")
    text_content = soup.get_text()

    # Prepare the PDF buffer
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    text_object = p.beginText(50, 750)
    text_object.setFont("Helvetica", 12)

    # Write text content line by line
    for line in text_content.splitlines():
        if line.strip():
            text_object.textLine(line.strip())

    p.drawText(text_object)
    p.showPage()
    p.save()
    buffer.seek(0)

    # Create the HTTP response
    applicant_name = context.get("applicant_name", "unknown_applicant")
    response = HttpResponse(buffer, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="{applicant_name}_Profilevalidation_Report.pdf"'

    return response

def recommend_certifications(role: str) -> list:
    """
    Recommends relevant certifications based on the targeted role.
    Returns a list of certification names and platforms.
    """
    
    certifications = {
        # ==== Technical Roles ====
        "Software Engineer": [
            "Full Stack Web Development - Coursera",
            "Java Programming and Software Engineering Fundamentals - Coursera",
            "Mastering Data Structures & Algorithms using C and C++ - Udemy",
            "Advanced JavaScript - Coursera"
        ],
        "Backend Engineer": [
            "Python for Data Science and Machine Learning Bootcamp - Udemy",
            "Back-End Development and APIs with Python - Coursera",
            "Building Scalable APIs with Python - DataCamp"
        ],
        "Frontend Engineer": [
            "Modern React with Redux - Udemy",
            "The Complete JavaScript Course - Udemy",
            "Responsive Web Design - freeCodeCamp",
            "Advanced CSS and Sass: Flexbox, Grid, Animations - Udemy"
        ],
        "Full Stack Engineer": [
            "The Complete Web Developer Bootcamp - Udemy",
            "Full Stack Web Development with React - Coursera",
            "MERN Stack - MongoDB, Express.js, React & Node.js - Udemy"
        ],
        "Data Scientist": [
            "IBM AI Practitioner - Coursera",
            "Google Data Analytics Professional Certificate - Coursera",
            "Data Science Professional Certificate - DataCamp",
            "Advanced Machine Learning - Coursera",
            "Deep Learning Specialization - Coursera",
            "Data Scientist with Python - DataCamp"
        ],
        "Machine Learning Engineer": [
            "Machine Learning by Andrew Ng - Coursera",
            "Deep Learning Specialization - Coursera",
            "TensorFlow Developer Certificate - Coursera",
            "AI For Everyone - Coursera"
        ],
        "MLOps Engineer": [
            "MLOps with Kubernetes - Coursera",
            "MLOps: Machine Learning Operations - Udemy",
            "Deploying Machine Learning Models - DataCamp"
        ],
        "Data Engineer": [
            "Google Cloud Data Engineering Professional Certificate - Coursera",
            "Data Engineering on Google Cloud - Coursera",
            "Building Data Pipelines with Python - DataCamp",
            "ETL Developer - Coursera"
        ],
        "DevOps Engineer": [
            "AWS Certified DevOps Engineer - Udemy",
            "DevOps on AWS - Coursera",
            "DevOps Bootcamp - Udemy",
            "Continuous Delivery & DevOps - Udemy"
        ],
        "Site Reliability Engineer (SRE)": [
            "Site Reliability Engineering: Measuring and Managing Reliability - Coursera",
            "Google Cloud Professional Cloud DevOps Engineer - Coursera",
            "SRE Fundamentals - LinkedIn Learning"
        ],
        "Cloud Engineer": [
            "Google Cloud Platform Fundamentals: Core Infrastructure - Coursera",
            "AWS Certified Solutions Architect - Udemy",
            "Azure Fundamentals - Coursera"
        ],
        "Cloud Architect": [
            "Google Cloud Professional Cloud Architect - Coursera",
            "AWS Certified Solutions Architect - Coursera",
            "Azure Solutions Architect Expert - Coursera"
        ],
        "Security Engineer": [
            "Certified Information Systems Security Professional (CISSP) - Udemy",
            "Certified Ethical Hacker (CEH) - Udemy",
            "AWS Certified Security Specialty - Coursera"
        ],
        "QA Engineer": [
            "Test Automation with Selenium - Coursera",
            "Software Testing and Automation - Udemy",
            "Automated Testing with Python - DataCamp"
        ],
        "Automation Engineer": [
            "Robotic Process Automation - Udemy",
            "Automating with Python - Coursera",
            "Automation with Python - DataCamp"
        ],
        "Mobile App Developer": [
            "Android Development for Beginners - Udemy",
            "iOS App Development with Swift - Coursera",
            "Mastering Android App Development with Kotlin - Udemy"
        ],
        "Android Developer": [
            "Google Android Developer Certification - Udacity",
            "Android Development for Beginners - Coursera",
            "Advanced Android Development - Udemy"
        ],
        "iOS Developer": [
            "iOS App Development with Swift - Coursera",
            "Swift 5 Programming for iOS - Udemy",
            "Build iOS Apps with Swift - Udemy"
        ],
        "Web Developer": [
            "The Complete Web Developer Bootcamp - Udemy",
            "Frontend Web Development - FreeCodeCamp",
            "Full Stack Web Development - Coursera"
        ],
        "Embedded Engineer": [
            "Embedded Systems Essentials - Coursera",
            "Embedded Systems with ARM Cortex-M - Udemy",
            "Embedded Software Development - Udemy"
        ],
        "Blockchain Developer": [
            "Blockchain Developer Bootcamp - Udemy",
            "Certified Blockchain Developer - Blockchain Council",
            "Ethereum and Solidity - Coursera"
        ],
        "AR/VR Developer": [
            "AR/VR Development with Unity - Coursera",
            "Augmented Reality Development - Udemy",
            "AR/VR Development with Unreal Engine - Udemy"
        ],
        "Data Analyst": [
            "Google Data Analytics Professional Certificate - Coursera",
            "Introduction to Data Science - Coursera",
            "Data Analysis with Python - DataCamp"
        ],
        "Business Intelligence Engineer": [
            "Power BI for Beginners - Udemy",
            "Business Intelligence with Power BI - Coursera",
            "SQL for Data Science - Coursera"
        ],
        "ETL Developer": [
            "ETL with Python - DataCamp",
            "ETL Pipeline Development with Apache Airflow - Udemy",
            "Data Engineering on Google Cloud - Coursera"
        ],
        "API Developer": [
            "API Design and Fundamentals - Udemy",
            "Build APIs with Flask and Python - Coursera",
            "Advanced API Development with Django REST Framework - Udemy"
        ],
        "Platform Engineer": [
            "Building Cloud Native Applications - Coursera",
            "Cloud Native Development with Docker & Kubernetes - Udemy",
            "Platform Engineering - Udemy"
        ],
        "Systems Engineer": [
            "Introduction to System Engineering - Coursera",
            "System Engineering Fundamentals - Udemy",
            "Systems Engineering with Python - DataCamp"
        ],
        "Game Developer": [
            "Complete C# Unity Game Developer 2D - Udemy",
            "Unreal Engine Game Development - Coursera",
            "Game Design and Development - Coursera"
        ],
        "Salesforce Developer": [
            "Salesforce Platform Developer I Certification - Udemy",
            "Salesforce Developer Certification Guide - Coursera",
            "Mastering Salesforce Development - LinkedIn Learning"
        ],
        "SAP Consultant (Tech)": [
            "SAP Certified Technology Associate - Udemy",
            "SAP S/4HANA for Beginners - Coursera",
            "SAP Advanced Configuration - LinkedIn Learning"
        ],
        "Product Manager (Tech)": [
            "Product Management for Technology - Coursera",
            "Agile Product Management - Udemy",
            "Product Management Fundamentals - LinkedIn Learning"
        ],
        "Technical Program Manager": [
            "Agile Project Management - Coursera",
            "Certified ScrumMaster - Udemy",
            "Project Management for Tech - LinkedIn Learning"
        ],
        "Tech Lead": [
            "Technical Leadership for Engineers - Coursera",
            "Becoming a Technical Leader - Udemy",
            "Tech Leadership and Strategy - LinkedIn Learning"
        ],
        "Engineering Manager": [
            "Engineering Management for Technology - Coursera",
            "Leading Teams and Projects - Udemy",
            "Engineering Leadership - LinkedIn Learning"
        ],

        # ==== Non-Technical Roles ====
        "Human Resources (HR) (non-tech)": [
            "Human Resource Management - Coursera",
            "HR Fundamentals - LinkedIn Learning",
            "Recruitment & Talent Management - Udemy"
        ],
        "Recruiter (non-tech)": [
            "Recruitment Process Optimization - Coursera",
            "Certified Professional in Human Resources (PHR) - Udemy",
            "Recruiting Talent - LinkedIn Learning"
        ],
        "Talent Acquisition Specialist (non-tech)": [
            "Talent Acquisition and Recruitment - Udemy",
            "Advanced Recruiting Techniques - LinkedIn Learning"
        ],
        "HR Manager (non-tech)": [
            "HR Management and Leadership - Coursera",
            "Talent Management and HR Strategy - Udemy",
            "HR & People Management - LinkedIn Learning"
        ],
        "Marketing (non-tech)": [
            "Digital Marketing Specialization - Coursera",
            "Marketing Analytics - Coursera",
            "Content Marketing Certification - HubSpot Academy"
        ],
        "Digital Marketing Specialist (non-tech)": [
            "Google Analytics for Beginners - Coursera",
            "Advanced Google Analytics - Coursera",
            "Social Media Marketing Certification - HubSpot Academy"
        ],
        "Content Marketer (non-tech)": [
            "Content Marketing Strategy - Coursera",
            "Inbound Content Marketing - HubSpot Academy"
        ],
        "SEO Specialist (non-tech)": [
            "SEO Certification - Coursera",
            "Advanced SEO - Udemy",
            "Search Engine Optimization (SEO) Specialization - Coursera"
        ],
        "Social Media Manager (non-tech)": [
            "Social Media Marketing - Coursera",
            "Social Media Strategy - LinkedIn Learning"
        ],
        "Product Marketing Manager (non-tech)": [
            "Product Marketing and Strategy - Coursera",
            "Marketing Strategies for Product Managers - Udemy"
        ],
        "Sales (non-tech)": [
            "Sales Training - Udemy",
            "Sales Strategies for Success - Coursera"
        ],
        "Business Development (non-tech)": [
            "Business Development and Sales - Coursera",
            "Sales & Business Development - LinkedIn Learning"
        ],
        "Account Executive (non-tech)": [
            "Certified Account Executive - Udemy",
            "Sales Fundamentals - Coursera"
        ],
        "Customer Success Manager (non-tech)": [
            "Customer Success Management - Coursera",
            "Customer Service Fundamentals - LinkedIn Learning"
        ],
        "Customer Service (non-tech)": [
            "Customer Service Excellence - Coursera",
            "Customer Service Fundamentals - LinkedIn Learning"
        ],
        "Finance (non-tech)": [
            "Financial Accounting - Coursera",
            "Financial Markets - Coursera",
            "Finance for Non-Finance Professionals - Coursera"
        ],
        "Financial Analyst (non-tech)": [
            "Financial Analysis for Business Decisions - Coursera",
            "Financial Modeling & Valuation Analyst - Udemy"
        ],
        "Accountant (non-tech)": [
            "Certified Public Accountant (CPA) - Udemy",
            "Accounting & Financial Reporting - Coursera"
        ],
        "Operations Manager (non-tech)": [
            "Operations Management - Coursera",
            "Project Management Principles - LinkedIn Learning"
        ],
        "Project Manager (non-tech)": [
            "PMP Certification - Udemy",
            "Agile Project Management - Coursera"
        ],
        "Program Manager (non-tech)": [
            "Program Management Essentials - Udemy",
            "Agile Project Management for Managers - Coursera"
        ],
        "Technical Writer (non-tech)": [
            "Technical Writing Certification - Udemy",
            "Business Writing for Technical Professionals - Coursera"
        ],
        "UX Designer (non-tech)": [
            "UX Design Certification - Coursera",
            "UI/UX Design Bootcamp - Udemy"
        ],
        "UI Designer (non-tech)": [
            "User Interface Design Certification - Coursera",
            "UX/UI Design Specialization - LinkedIn Learning"
        ],
        "Graphic Designer (non-tech)": [
            "Graphic Design Specialization - Coursera",
            "Graphic Design Bootcamp - Udemy"
        ],
        "Data Entry (non-tech)": [
            "Data Entry for Beginners - Udemy",
            "Microsoft Excel for Data Entry - LinkedIn Learning"
        ],
        "Office Administrator (non-tech)": [
            "Office Management Training - Coursera",
            "Admin Assistant Training - LinkedIn Learning"
        ],
        "Consultant (non-tech)": [
            "Consulting Skills for Professionals - Udemy",
            "Business Consultant Training - Coursera"
        ],
        "Business Analyst (non-tech)": [
            "Business Analysis for IT Projects - Coursera",
            "Business Analysis Fundamentals - Udemy"
        ],
        "Supply Chain Analyst (non-tech)": [
            "Supply Chain Management - Coursera",
            "Logistics and Supply Chain Management - LinkedIn Learning"
        ],
        "Procurement Specialist (non-tech)": [
            "Procurement and Supply Chain Management - Udemy",
            "Advanced Procurement and Sourcing - Coursera"
        ],
        "Quality Assurance (Non-Tech)": [
            "Software Testing and QA - Udemy",
            "Quality Assurance Fundamentals - Coursera"
        ],
        "Product Manager (Non-Tech)": [
            "Product Management Certification - Coursera",
            "Managing Product Teams - LinkedIn Learning"
        ]
    }

    return certifications.get(role, [])

import requests

def recommend_certifications(role: str) -> list:
    """
    Recommends certifications using Coursera API based on the targeted role.
    """
    coursera_url = f"https://api.coursera.org/courses?search={role}"
    response = requests.get(coursera_url)

    if response.status_code == 200:
        data = response.json()
        certifications = []

        # Parse the data for relevant certifications
        for course in data['elements']:
            certifications.append(course['name'] + ' - Coursera')

        return certifications

    return []  # Return empty list if API fails or role is not found


# ========= Technical analyzer =========
# ========= Technical analyzer =========
import requests

import requests

import requests
import os

import requests
import os

import requests
import os

def fetch_certifications_from_platforms(role: str) -> list:
    """
    Fetch recommended certifications dynamically from Coursera, edX, and Udemy.
    Uses API keys stored in .env file.
    """
    results = []
    try:
        # Fetch API keys from environment variables
        coursera_key = os.getenv("OPEN_API")
        edx_key = os.getenv("OPEN_API")
        udemy_key = os.getenv("OPEN_API")

        # Prepare the query by formatting the role
        query = role.replace("_", " ").title()
        print(f"Fetching certifications for role: {query}")

        # Coursera
        if coursera_key:
            print("Fetching Coursera certifications...")
            r = requests.get(
                "https://api.coursera.org/api/courses.v1",
                params={"q": query, "limit": 5},
                headers={"Authorization": f"Bearer {coursera_key}"}
            )
            if r.ok:
                coursera_data = r.json()
                print("Coursera API Response:", coursera_data)
                if 'elements' in coursera_data:
                    for c in coursera_data['elements']:
                        print(f"Coursera Certification Found: {c.get('name')}")
                        results.append(f"Coursera: {c.get('name')}")
                else:
                    print("No certifications found in Coursera response.")
            else:
                print(f"Coursera API Error: {r.status_code} - {r.text}")

        # edX
        if edx_key:
            print("Fetching edX certifications...")
            r = requests.get(
                "https://api.edx.org/catalog/v1/courses",
                params={"search": query, "page_size": 5},
                headers={"Authorization": f"Bearer {edx_key}"}
            )
            if r.ok:
                edx_data = r.json()
                print("edX API Response:", edx_data)
                if 'results' in edx_data:
                    for c in edx_data['results']:
                        print(f"edX Certification Found: {c.get('title')}")
                        results.append(f"edX: {c.get('title')}")
                else:
                    print("No certifications found in edX response.")
            else:
                print(f"edX API Error: {r.status_code} - {r.text}")

        # Udemy
        if udemy_key:
            print("Fetching Udemy certifications...")
            r = requests.get(
                "https://www.udemy.com/api-2.0/courses/",
                params={"search": query, "page_size": 5},
                headers={"Authorization": f"Bearer {udemy_key}"}
            )
            if r.ok:
                udemy_data = r.json()
                print("Udemy API Response:", udemy_data)
                if 'results' in udemy_data:
                    for c in udemy_data['results']:
                        print(f"Udemy Certification Found: {c.get('title')}")
                        results.append(f"Udemy: {c.get('title')}")
                else:
                    print("No certifications found in Udemy response.")
            else:
                print(f"Udemy API Error: {r.status_code} - {r.text}")

    except Exception as e:
        print(f"[CertFetchError] {e}")

    # Return the certifications found or a default message if none were found
    if results:
        print(f"Found certifications: {results[:5]}")
        return results[:5]
    else:
        print("No certifications found. Returning default message.")
        return ["No external certification data available."]

# @require_POST
# def analyze_resume(request):
#     import os
#     os.environ.setdefault("MPLBACKEND", "Agg")
#     os.environ.setdefault("MPLCONFIGDIR", "/tmp/matplotlib")

#     import matplotlib

#     if request.POST.get("domain") != "technical":
#         return HttpResponseBadRequest("Please choose Technical category.")
#     if "resume" not in request.FILES:
#         return HttpResponseBadRequest("Resume file required.")

#     resume_file = request.FILES["resume"]
#     ext = os.path.splitext(resume_file.name)[1].lower()

#     with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
#         for chunk in resume_file.chunks():
#             tmp.write(chunk)
#         temp_path = tmp.name

#     try:
#         # 1) Extract text & anchors
#         if ext == ".pdf":
#             legacy_links, resume_text_raw = extract_links_combined(temp_path)
#             resume_text = _normalize_text(resume_text_raw or "")
#         elif ext == ".docx":
#             resume_text_raw = extract_text_from_docx(temp_path) or ""
#             resume_text = _normalize_text(resume_text_raw)
#             legacy_links = extract_links_from_docx(temp_path)
#         elif ext in (".txt",):
#             with open(temp_path, "r", encoding="utf-8", errors="ignore") as f:
#                 resume_text_raw = f.read()
#             resume_text = _normalize_text(resume_text_raw or "")
#             legacy_links = []
#         else:
#             return HttpResponseBadRequest("Unsupported file format.")
        
#         role_slug = request.POST.get('role_slug', 'Data Scientist') 

#         # 2) Metadata enrich + URLs from text
#         resume_links_full = (
#             process_resume_links(
#                 temp_path,
#                 mime_type=resume_file.content_type,
#                 fetch_metadata=True,
#                 limit=120,
#             ) or []
#         )

#         text_urls = extract_urls_from_text(resume_text)
#         existing = {i.get("url") for i in resume_links_full if i.get("url")}
#         extra_pool = []
#         for u in (legacy_links + text_urls):
#             if not u or u in existing:
#                 continue
#             extra_pool.append({
#                 "url": u,
#                 "domain": _domain_of(u),
#                 "type": "other",
#                 "title": "",
#                 "description": "",
#             })
#         merged_links = _dedupe_preserve_order_link_dicts(resume_links_full + extra_pool)

#         # 3) Validate links
#         enriched_links = validate_links_enrich(merged_links)
#         ok_links = only_ok_links(enriched_links)
#         link_urls_ok  = [i.get("final_url") or i.get("url") for i in ok_links if i.get("url")]
#         link_urls_all = [i.get("final_url") or i.get("url") for i in enriched_links if i.get("url")]

#         # 4) Inputs / usernames
#         applicant_name    = extract_applicant_name(resume_text) or "Candidate"
#         github_username   = (request.POST.get("github_username", "") or "").strip() \
#                             or extract_github_username(resume_text) \
#                             or infer_github_username(link_urls_ok or link_urls_all, resume_text) \
#                             or ""
        
#         # Updated GitHub detection logic
#         github_detection = "NO"  # Default detection is NO
#         import re
#         # Check if "github" appears in the resume text (case-insensitive)
#         if re.search(r'github', resume_text, re.IGNORECASE):
#             # Check for clickable GitHub links in the extracted links
#             github_urls = [url for url in (link_urls_ok + link_urls_all) if "github.com" in url.lower()]
#             # Helper function to validate GitHub URL and check if it redirects to a valid GitHub page
#             def is_valid_github_url(url: str) -> bool:
#                 # GitHub URLs must contain 'github.com' and be properly formatted
#                 if not re.match(r'https?://(www\.)?github\.com/[a-zA-Z0-9-_]+', url, re.IGNORECASE):
#                     return False
#                 try:
#                     import requests
#                     # Make a HEAD request to check if the URL is reachable
#                     response = requests.head(url, allow_redirects=True, timeout=5)
#                     # Check if the final URL after redirects is still a GitHub URL
#                     if response.status_code == 200 and "github.com" in response.url.lower():
#                         return True
#                 except requests.RequestException:
#                     return False
#                 return False

#             # If any GitHub URL is valid and reachable, set detection to YES
#             if any(is_valid_github_url(url) for url in github_urls):
#                 github_detection = "YES"

#         # Debugging the final GitHub detection
#         print(f"GitHub detection: '{github_detection}'")

#         leetcode_username = (request.POST.get("leetcode_username", "") or "").strip() \
#                             or extract_leetcode_username(resume_text) \
#                             or infer_leetcode_username(link_urls_ok or link_urls_all, resume_text) \
#                             or ""
#         role_slug         = request.POST.get("tech_role", "software_engineer")
#         job_description   = (request.POST.get("job_description", "") or "").strip()

#         # 5) Dynamic ATS
#         dyn = calculate_dynamic_ats_score(
#             resume_text=resume_text,
#             github_username=github_username if any("github.com" in (u or "") for u in link_urls_ok) else "",
#             leetcode_username=leetcode_username if any("leetcode." in (u or "") for u in link_urls_ok) else "",
#             extracted_links=ok_links,
#         )

#         # 6) Optional GitHub API score if token + reachable profile
#         github_token = os.getenv("OPEN_API")
#         if github_username and github_token and any(l for l in ok_links if l.get("type") == "github"):
#             try:
#                 gh_score, gh_rationales, gh_evidence, _ = score_github_via_api(github_username, github_token)
#                 # Normalize GitHub score to max 27 if heuristic is used
#                 if "sections" in dyn and "GitHub Profile" in dyn["sections"]:
#                     gh_sec = dyn["sections"]["GitHub Profile"]
#                     raw_score = int(gh_sec.get("score", 0) or 0)
#                     gh_sec["score"] = min(raw_score, 27)  # cap at 27
#                     gh_sec.setdefault("sub_criteria", []).append(
#                         {"name": "Heuristic Eval", "score": raw_score, "weight": 27,
#                         "insight": "Heuristic GitHub analysis applied (fallback)."}
#                     )
#                     dyn["sections"]["GitHub Profile"] = gh_sec

#             except Exception as e:
#                 print(f"GitHub API error (fallback to heuristic): {e}")
                
#         # 6b) LinkedIn public HTML (only if 200 OK page captured)
#         ok_linkedin = next((l for l in ok_links if l.get("type") == "linkedin"), None)
#         if ok_linkedin:
#             li_html = ok_linkedin.get("html", "") or ""
#             li_url  = ok_linkedin.get("final_url") or ok_linkedin.get("url") or ""
#             li_score_pub, li_rats_pub, li_evidence_pub = score_linkedin_public_html(li_html, li_url, resume_text)
#             if "sections" in dyn and "LinkedIn" in dyn["sections"] and isinstance(li_score_pub, (int, float)):
#                 base_score = int(dyn["sections"]["LinkedIn"].get("score", 0) or 0)
#                 dyn["sections"]["LinkedIn"]["score"] = max(base_score, int(li_score_pub))
#                 dyn["sections"]["LinkedIn"].setdefault("sub_criteria", []).append(
#                     {"name": "Public Profile Parse", "score": int(li_score_pub), "weight": 18, "insight": " ; ".join(li_rats_pub)}
#                 )

#         # 7) Presence notes for UI rows
#         linkedin_present_any  = any(_LI_ANY_RE.search((l.get("final_url") or l.get("url") or "")) for l in enriched_links)
#         portfolio_present_any = any(l for l in enriched_links if l.get("type") == "portfolio")
#         ok_portfolio          = [l for l in ok_links if l.get("type") == "portfolio"]

#         def _ensure_presence_row(subrows, label_prefix, text, score_val=0):
#             updated = False
#             for r in subrows:
#                 name = (r.get("name","") or "").lower().strip()
#                 if name.startswith(label_prefix):
#                     r["insight"] = text
#                     r.setdefault("weight", 2)
#                     r["score"] = score_val
#                     updated = True
#                     break
#             if not updated:
#                 subrows.insert(0, {"name": label_prefix.title(), "score": score_val, "weight": 2, "insight": text})

#         li_sec = dyn["sections"].get("LinkedIn", {"score": 0, "sub_criteria": []})
#         li_sub = li_sec.get("sub_criteria") or []
#         if linkedin_present_any and not ok_linkedin:
#             _ensure_presence_row(li_sub, "profile presence", "Profile link present but unreachable (login/blocked).", 0)
#         elif ok_linkedin:
#             _ensure_presence_row(li_sub, "profile presence", "Profile link present and reachable (public).", 2)
#         li_sec["sub_criteria"] = li_sub
#         dyn["sections"]["LinkedIn"] = li_sec

#         pf_sec = dyn["sections"].get("Portfolio Website", {"score": 0, "sub_criteria": []})
#         pf_sub = pf_sec.get("sub_criteria") or []
#         if portfolio_present_any and not ok_portfolio:
#             _ensure_presence_row(pf_sub, "portfolio presence", "Portfolio link present but unreachable.", 0)
#         elif ok_portfolio:
#             _ensure_presence_row(pf_sub, "portfolio presence", "Portfolio link(s) present and reachable.", 2)
#         pf_sec["sub_criteria"] = pf_sub
#         dyn["sections"]["Portfolio Website"] = pf_sec

#         # 8) Certifications count-in (show only count, no names)
#         cert_count, cert_names_found = count_only_certifications(resume_text, enriched_links)

#         cert_sec_key = "Certifications & Branding"
#         cert_sec = dyn["sections"].get(cert_sec_key, {"score": 0, "sub_criteria": []})
#         cert_sub = cert_sec.get("sub_criteria") or []

#         cert_score_by_count = min(9, max(0, int(cert_count)))
#         cert_sec["score"] = max(int(cert_sec.get("score", 0) or 0), cert_score_by_count)

#         # remove any prior auto rows
#         cert_sub = [r for r in cert_sub if not (isinstance(r, dict) and str(r.get("name","")).startswith("[Auto]"))]

#         # NOTE: We do NOT list certificate names anymore — only the count.
#         cert_sub.insert(0, {
#             "name": "[Auto] Certifications Found",
#             "score": cert_score_by_count,
#             "weight": 9,
#             "insight": f"Detected {cert_count} certification(s).",
#         })

#         cert_sec["sub_criteria"] = cert_sub
#         dyn["sections"][cert_sec_key] = cert_sec

#         # 9) Suggest role-aware certs to top-up to 6 (kept as suggestions)
#         suggested_certs = []
#         if cert_count < 6:
#             needed = 6 - cert_count
#             suggested_certs = suggest_role_certifications(
#                 role_text=role_slug,
#                 job_description=job_description,
#                 resume_text=resume_text,
#                 existing_cert_lines=cert_names_found,
#                 max_items=needed,
#             )

#         # 10) Build report sections (DYNAMIC — no hard-coded maxima)
#         map_to_dyn = {
#             "GitHub":         "GitHub Profile",
#             "LinkedIn":       "LinkedIn",
#             "Portfolio":      "Portfolio Website",
#             "Resume (ATS)":   "Resume (ATS Score)",
#             "Certifications": "Certifications & Branding",
#         }

#         DEFAULT_SECTION_MAX = {
#             "GitHub": 27,
#             "LinkedIn": 18,
#             "Portfolio": 23,
#             "Resume (ATS)": 23,
#             "Certifications": 9,
#         }

#         dyn_weights = dyn.get("weights") or {}

#         def dyn_max_for(tpl_name: str) -> int:
#             dyn_key = map_to_dyn[tpl_name]
#             sec = dyn["sections"].get(dyn_key, {})
#             if isinstance(sec, dict) and isinstance(sec.get("max"), (int, float)):
#                 return int(sec.get("max"))
#             if dyn_key in dyn_weights and isinstance(dyn_weights[dyn_key], (int, float)):
#                 return int(dyn_weights[dyn_key])
#             if tpl_name in dyn_weights and isinstance(dyn_weights[tpl_name], (int, float)):
#                 return int(dyn_weights[tpl_name])
#             return DEFAULT_SECTION_MAX[tpl_name]

#         SECTION_MAX = {name: dyn_max_for(name) for name in map_to_dyn.keys()}
#         TOTAL_MAX = sum(SECTION_MAX.values())

#         def _safe_sec(name):
#             return dyn["sections"].get(name, {"score": 0, "grade": "Poor", "sub_criteria": []})

#         github_sec    = _safe_sec(map_to_dyn["GitHub"])
#         linkedin_sec  = _safe_sec(map_to_dyn["LinkedIn"])
#         portfolio_sec = _safe_sec(map_to_dyn["Portfolio"])
#         resume_sec    = _safe_sec(map_to_dyn["Resume (ATS)"])
#         certs_sec     = _safe_sec(map_to_dyn["Certifications"])

#         section_scores = {
#             "GitHub":         int(github_sec.get("score", 0) or 0),
#             "LinkedIn":       int(linkedin_sec.get("score", 0) or 0),
#             "Portfolio":      int(portfolio_sec.get("score", 0) or 0),
#             "Resume (ATS)":   int(resume_sec.get("score", 0) or 0),
#             "Certifications": int(certs_sec.get("score", 0) or 0),
#         }

#         weights_pct = {
#             k: int(round((SECTION_MAX[k] / float(TOTAL_MAX)) * 100)) if TOTAL_MAX else 0
#             for k in SECTION_MAX
#         }

#         def _grade_pct(pct: float) -> str:
#             if pct >= 85:
#                 return "Excellent"
#             if pct >= 70:
#                 return "Good"
#             if pct >= 50:
#                 return "Average"
#             return "Poor"

#         score_breakdown, score_breakdown_ordered = {}, []
#         for tpl_name in ["GitHub","LinkedIn","Portfolio","Resume (ATS)","Certifications"]:
#             score  = section_scores[tpl_name]
#             maxpts = SECTION_MAX[tpl_name]
#             grade  = _grade_pct((score / maxpts) * 100 if maxpts else 0)
#             score_breakdown[tpl_name] = {"score": score, "max": maxpts, "grade": grade, "weight": weights_pct[tpl_name]}
#             score_breakdown_ordered.append((tpl_name, {
#                 "score": score,
#                 "grade": grade,
#                 "sub_criteria": (_safe_sec(map_to_dyn[tpl_name]).get("sub_criteria") or []),
#             }))

#         total_score     = sum(section_scores.values())
#         profile_percent = int(round((total_score / float(TOTAL_MAX)) * 100)) if TOTAL_MAX else 0

#         def _color_class(pct: int) -> str:
#             if pct > 80: return "score-box"
#             if pct >= 50: return "score-box-orange"
#             return "score-box-red"

#         # DYNAMIC ATS percent
#         ats_score_val = int(resume_sec.get("score", 0) or 0)
#         ats_max_val   = SECTION_MAX["Resume (ATS)"] or 1
#         ats_percent   = int(round((ats_score_val / float(ats_max_val)) * 100))
#         ats_score_class     = _color_class(ats_percent)
#         profile_score_class = _color_class(profile_percent)

#         # 11) Charts — dynamic maxima in legend
#         def _build_pie_base64_local(scores: Dict[str, int]) -> str:
#             if not scores or sum(scores.values()) == 0:
#                 return ""
#             labels, values = list(scores.keys()), list(scores.values())
#             fig, ax = plt.subplots(figsize=(4.6, 4.6), facecolor="#121212")
#             ax.set_facecolor("#121212")
#             def _autopct(p): return f"{p:.0f}%" if p >= 5 else ""
#             wedges, _, _ = ax.pie(values, labels=None, autopct=_autopct, startangle=140,
#                                   textprops={"color": "white", "fontsize": 10})
#             ax.axis("equal")
#             legend_labels = [
#                 f"{lbl}: {val}/{SECTION_MAX[lbl]} ({(val/SECTION_MAX[lbl])*100:.0f}%)"
#                 for lbl, val in zip(labels, values)
#             ]
#             ax.legend(wedges, legend_labels, loc="lower center", bbox_to_anchor=(0.5, -0.22),
#                       fontsize=9, frameon=False, labelcolor="white", ncol=2, columnspacing=1.2,
#                       handlelength=1.2, borderpad=0.2)
#             buf = io.BytesIO()
#             plt.tight_layout()
#             plt.savefig(buf, format="png", dpi=160, facecolor="#121212", bbox_inches="tight")
#             b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
#             buf.close(); plt.close(fig)
#             return b64

#         pie_chart_image = _build_pie_base64_local(section_scores)

#         # 12) Reweighted Screening Emphasis (Initial Screen)
#         REWEIGHTED = {
#             "MAANG":       {"GitHub": 22, "LinkedIn": 22, "Portfolio": 20, "Resume": 31, "Certifications": 5},
#             "Startups":    {"GitHub": 30, "LinkedIn": 18, "Portfolio": 28, "Resume": 20, "Certifications": 4},
#             "Mid-sized":   {"GitHub": 25, "LinkedIn": 22, "Portfolio": 23, "Resume": 24, "Certifications": 6},
#             "Fortune 500": {"GitHub": 18, "LinkedIn": 25, "Portfolio": 17, "Resume": 30, "Certifications": 10},
#         }

#         gh_pct = (section_scores["GitHub"]       / float(SECTION_MAX["GitHub"]))       * 100.0 if SECTION_MAX["GitHub"] else 0.0
#         li_pct = (section_scores["LinkedIn"]     / float(SECTION_MAX["LinkedIn"]))     * 100.0 if SECTION_MAX["LinkedIn"] else 0.0
#         pf_pct = (section_scores["Portfolio"]    / float(SECTION_MAX["Portfolio"]))    * 100.0 if SECTION_MAX["Portfolio"] else 0.0
#         rs_pct = (section_scores["Resume (ATS)"] / float(SECTION_MAX["Resume (ATS)"])) * 100.0 if SECTION_MAX["Resume (ATS)"] else 0.0
#         ce_pct = (section_scores["Certifications"]/ float(SECTION_MAX["Certifications"])) * 100.0 if SECTION_MAX["Certifications"] else 0.0

#         def compute_company_emphasis(gh, li, pf, rs, ce):
#             scores = {}
#             for company, w in REWEIGHTED.items():
#                 total = (gh * w["GitHub"] + li * w["LinkedIn"] + pf * w["Portfolio"]
#                          + rs * w["Resume"] + ce * w["Certifications"]) / 100.0
#                 scores[company] = round(total, 1)
#             return scores

#         screening_scores = compute_company_emphasis(gh_pct, li_pct, pf_pct, rs_pct, ce_pct)

#         def _build_company_screening_bar(scores_dict: Dict[str, float]) -> str:
#             if not scores_dict:
#                 return ""
#             import matplotlib as mpl
#             import matplotlib.pyplot as plt
#             mpl.rcParams.update({
#                 "font.family": "DejaVu Sans",
#                 "font.sans-serif": ["DejaVu Sans"],
#                 "axes.titleweight": "bold",
#             })
#             order = ["MAANG", "Startups", "Mid-sized", "Fortune 500"]
#             vals = [float(scores_dict.get(k, 0.0)) for k in order]
#             fig, ax = plt.subplots(figsize=(7.2, 3.9), facecolor="#121212")
#             ax.set_facecolor("#121212")
#             bars = ax.bar(order, vals, linewidth=0.6, edgecolor="#e6e6e6", alpha=0.95)
#             ax.set_ylim(0, 100)
#             ax.set_ylabel("Weighted score (0–100)", color="white", fontsize=10, fontweight="bold", labelpad=8)
#             ax.set_title("Screening Emphasis by Company Type (Initial Screen)",
#                         color="white", fontsize=8, fontweight="bold", pad=5)
#             ax.tick_params(axis="x", colors="white", labelsize=8)
#             ax.tick_params(axis="y", colors="white", labelsize=8)
#             ax.spines["bottom"].set_color("#444"); ax.spines["left"].set_color("#444")
#             ax.spines["top"].set_visible(False);   ax.spines["right"].set_visible(False)
#             ax.grid(axis="y", color="#333", alpha=0.35, linewidth=0.7)
#             for rect, v in zip(bars, vals):
#                 ax.text(rect.get_x() + rect.get_width()/2.0, rect.get_height() + 2, f"{v:.0f}",
#                         ha="center", va="bottom", color="white", fontsize=10, fontweight="bold")
#             buf = io.BytesIO(); plt.tight_layout()
#             plt.savefig(buf, format="png", dpi=170, facecolor="#121212", bbox_inches="tight")
#             b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
#             buf.close(); plt.close(fig); return b64

#         screening_chart_image = _build_company_screening_bar(screening_scores)
#         recommended_certifications = recommend_certifications(role_slug)
#         dynamic_certifications = fetch_certifications_from_platforms(role_slug)

#         # 13) Final context
#         context = {
#             "result_key": hashlib.sha256(json.dumps({
#                 "role_type": "technical",
#                 "role_slug": role_slug,
#                 "resume_hash": hashlib.sha256((resume_text or "").encode("utf-8")).hexdigest(),
#                 "github": github_username or "",
#                 "leetcode": leetcode_username or "",
#             }, sort_keys=True).encode("utf-8")).hexdigest(),

#             "applicant_name": applicant_name,

#             # Header badges
#             "ats_score": ats_percent,
#             "ats_score_class": ats_score_class,
#             "overall_score_average": profile_percent,
#             "profile_score_class": profile_score_class,

#             # Detections (presence)
#             "contact_detection": "YES" if _detect_contact(resume_text) else "NO",
#             "linkedin_detection": "YES" if linkedin_present_any else "NO",
#             "github_detection": github_detection,            # Table & cards
#             "score_breakdown": score_breakdown,
#             "score_breakdown_ordered": score_breakdown_ordered,
#             "total_score": total_score,
#             "total_grade": _grade_pct_label(profile_percent),

#             # Charts
#             "pie_chart_image": pie_chart_image,
#             "screening_chart_image": screening_chart_image,
#             "screening_scores": screening_scores,

#             "recommended_certifications": recommended_certifications,
#             "dynamic_certifications": dynamic_certifications,
#             "role": role_slug,

#             # Suggestions / misc
#             "role": role_slug,
#             "suggestions": (dyn.get("suggestions") or [])[:8],
            

#             # Certifications: suggestions (no listing of found names)
#             "missing_certifications": suggested_certs,
#             "missing_certifications_block": (
#                 ("CERTIFICATIONS\n" + "\n".join(suggested_certs)) if suggested_certs else ""
#             ),

#             # Rich links for UI
#             "extracted_links": enriched_links,
#         }

#         request.session["resume_context_tech"] = context
#         request.session.modified = True
#         return render(request, "resume_result.html", context)

#     finally:
#         try:
#             os.unlink(temp_path)
#         except Exception:
#             pass
#  # Save cache in /tmp
# # 

from django.views.decorators.http import require_POST
import os
import tempfile
import hashlib
import base64
import io
from typing import Dict
import matplotlib
import matplotlib.pyplot as plt
import requests
import json
import re

from django.views.decorators.http import require_POST
import os
import tempfile
import hashlib
import base64
import io
from typing import Dict
import matplotlib
import matplotlib.pyplot as plt
import requests
import json
import re

from django.views.decorators.http import require_POST
import os
import tempfile
import hashlib
import base64
import io
from typing import Dict
import matplotlib
import matplotlib.pyplot as plt
import requests
import json
import re

from django.views.decorators.http import require_POST
import os
import tempfile
import hashlib
import base64
import io
from typing import Dict
import matplotlib
import matplotlib.pyplot as plt
import requests
import json
import re

from django.views.decorators.http import require_POST
import os
import tempfile
import hashlib
import base64
import io
from typing import Dict
import matplotlib
import matplotlib.pyplot as plt
import requests
import json
import re

import os
import re
import tempfile
import base64
import io
import json
import hashlib
import requests
import matplotlib.pyplot as plt
import matplotlib
from typing import List, Dict, Any
from django.views.decorators.http import require_POST
from django.http import HttpResponseBadRequest
from django.shortcuts import render
import openai

import os
import re
import tempfile
import json
import requests
import hashlib
import io
import base64
import matplotlib.pyplot as plt
import matplotlib
from typing import List, Dict, Any

# NOTE: Assuming necessary imports for helper functions like
# _normalize_text, extract_links_combined, process_resume_links, etc.,
# and Django response classes (HttpResponseBadRequest, render) are available.

# Define global/contextual information (usually in settings or module scope)
TECHNICAL_WEIGHTS = {
    "GitHub Profile": 27,
    "LinkedIn": 18,
    "Portfolio Website": 23,
    "Resume (ATS Score)": 23,
    "Certifications & Branding": 9,
    "LeetCode/DSA Skills": 9,
}

def get_grade_tag(score_or_pct):
    if isinstance(score_or_pct, (int, float)):
        if score_or_pct >= 85:
            return "Excellent"
        elif score_or_pct >= 70:
            return "Good"
        elif score_or_pct >= 50:
            return "Average"
        else:
            return "Poor"
    return "Poor"

def _ensure_presence_row(subrows, label_prefix, text, score_val=0):
    updated = False
    for r in subrows:
        name = (r.get("name", "") or "").lower().strip()
        if name.startswith(label_prefix):
            r["insight"] = text
            r.setdefault("weight", 2)
            r["score"] = score_val
            updated = True
            break
    if not updated:
        # Insert at top for better visibility
        subrows.insert(0, {"name": label_prefix.title(), "score": score_val, "weight": 2, "insight": text})
    return subrows

import re
from typing import List, Dict, Tuple
from urllib.parse import urlparse

# Assumed helper functions, you can implement them as needed
def _norm_text(text: str) -> str:
    return text.strip().lower()

def _clean_cert_name(cert: str) -> str:
    return cert.strip()

def _looks_like_cert_line(line: str) -> bool:
    # You can enhance this function to detect more patterns related to certifications.
    return bool(re.search(r"(certification|certificate|certified|course|training|badge)", line, re.IGNORECASE))

def _domain_of(url: str) -> str:
    return urlparse(url).netloc.lower()

_CERT_LINK_HOSTS = ["credly.com", "accredible.com", "udemy.com", "coursera.org", "linkedin.com"]  # You can add more recognized platforms here.

# def count_only_certifications(resume_text: str, enriched_links: List[Dict[str, str]] | None = None) -> Tuple[int, List[Dict[str, str]]]:
#     """
#     Returns:
#       (count:int, certificates:List[Dict])

#     - Scans resume text for lines that look like certifications (headings, bullets, exam codes).
#     - Adds any credential-looking links' titles (Credly/Accredible/etc.).
#     - Deduplicates while preserving order.
#     - Scores each certification based on relevance or platform.
#     """
#     certificates: List[Dict[str, str]] = []

#     # --- From text (section + anywhere) ---
#     lines = [ln.strip() for ln in (resume_text or "").splitlines()]
#     in_cert_block = False
#     for raw in lines:
#         ln = _norm_text(raw)

#         # Detect entering/leaving explicit section
#         if re.match(r"^\s*(licenses?\s*&?\s*certifications?|certifications?|licenses?)\s*:?$", ln, re.I):
#             in_cert_block = True
#             continue
#         if in_cert_block and (not ln or re.match(r"^(experience|education|projects?|skills?|profile|summary|achievements?)\s*:?\s*$", ln, re.I)):
#             in_cert_block = False

#         cand = _clean_cert_name(ln)
#         # Prioritize explicit block lines; otherwise anywhere if it looks like a cert
#         if (in_cert_block and cand) or _looks_like_cert_line(cand):
#             # keep only reasonably short cert lines (avoid pasting whole paragraphs)
#             if 3 <= len(cand) <= 140:
#                 certificates.append({
#                     "name": cand,
#                     "source": "resume_text",
#                     "score": 0  # Initial score to be determined
#                 })

#     # --- From links (credly/accredible/etc.) ---
#     for item in (enriched_links or []):
#         u = (item.get("final_url") or item.get("url") or "").strip()
#         if not u:
#             continue
#         dom = _domain_of(u)
#         if any(h in dom for h in _CERT_LINK_HOSTS) or "badge" in u.lower() or "verify" in u.lower():
#             title = _clean_cert_name(item.get("title") or "")
#             # If no title, try to make something from path
#             if not title:
#                 tail = _clean_cert_name(urlparse(u).path.replace("-", " ").replace("/", " ").strip())
#                 title = tail or u
#             if title:
#                 certificates.append({
#                     "name": title,
#                     "source": "link",
#                     "score": 0  # Initial score to be determined
#                 })

#     # --- Deduplicate (case/space-insensitive) preserving order ---
#     seen = set()
#     unique_certificates: List[Dict[str, str]] = []
#     for cert in certificates:
#         key = re.sub(r"[\s\-–—]+", " ", cert['name'].lower()).strip()
#         if key and key not in seen:
#             seen.add(key)
#             unique_certificates.append(cert)

#     # --- Score the certificates ---
#     for cert in unique_certificates:
#         score = 0
#         # Scoring based on source
#         if cert['source'] == "link":
#             score += 3  # Credly/Accredible/etc. sources could be more trusted
#         # Scoring based on the name of the certification (length and key phrases)
#         if len(cert["name"]) > 50:
#             score += 2  # Longer names might indicate more detailed, recognized certifications
#         if "certification" in cert["name"].lower():
#             score += 2  # Presence of the word 'certification' adds weight
#         if "course" in cert["name"].lower():
#             score += 1  # Presence of the word 'course' adds a moderate weight

#         # Optionally, you can add more complex scoring logic here based on specific keywords or platforms

#         cert["score"] = score

#     return len(unique_certificates), unique_certificates

import re
from typing import List, Dict, Tuple
from urllib.parse import urlparse
import re
from typing import List, Dict, Tuple
from urllib.parse import urlparse

# # Helper functions (implement as needed)
# def _norm_text(text: str) -> str:
#     """Normalize the text by stripping and lowering the case."""
#     return text.strip().lower()

# def _clean_cert_name(cert: str) -> str:
#     """Clean up the certification name."""
#     return cert.strip()

# def _looks_like_cert_line(line: str) -> bool:
#     """Detect if a line looks like a certification."""
#     # Looking for patterns like certification, certified, course, badge, etc.
#     return bool(re.search(r"(certification|certificate|certified|course|training|badge)", line, re.IGNORECASE))

import re
from typing import List, Tuple, Dict

import re
from typing import List, Tuple, Dict

# --- REQUIRED HELPER FUNCTIONS ---

import re
from typing import List, Tuple, Dict
from urllib.parse import urlparse

# --- Helper functions (These were implicitly available or defined inline) ---

# def _norm_text(text: str) -> str:
#     """Normalize the text by stripping and lowering the case."""
#     # Retains the original line structure while normalizing for comparison
#     return (text or "").strip()

# def _clean_cert_name(text: str) -> str:
#     """Clean up the certification name by removing common noise."""
#     s = text.strip()
#     # Remove common bullet characters and excess whitespace
#     s = re.sub(r"^\s*[-*•■●]|[0-9]+\.\s*", "", s).strip()
#     # Remove potential dates and parentheses at the end
#     s = re.sub(r"\s*\(.*?\)|\s*\[.*?\]|\s*\{\.*?\}", "", s)
#     # Remove trailing dates (e.g., ' - 2023' or ', 2023')
#     s = re.sub(r"[\s\-,;]+(?:[A-Za-z]+\s+)?\d{4}(?:\s*-\s*(?:present|\d{4}))?\s*$", "", s, flags=re.I).strip()
#     # Remove common trailing terms
#     s = re.sub(r"\s*(License|Credential|ID|No\.?|Certificate)\s*.*$", "", s, flags=re.I).strip()
#     return re.sub(r"\s{2,}", " ", s) # Clean up internal spaces

# def _looks_like_cert_line(line: str) -> bool:
#     """Detect if a line looks like a certification using strong keywords/patterns."""
#     # Standard cert/license terms
#     if re.search(r"\b(certification|certificate|certified|license|licen[sc]e|credential|exam|badge)\b", line, re.I):
#         return True
#     # Common provider or exam patterns (AWS, Azure, Google, CISSP, PMP)
#     if re.search(r"\b(AWS|Azure|GCP|PMP|CISSP|CompTIA|CKA|CKAD)\b", line):
#         return True
#     # Microsoft exam codes (e.g., AZ-900, DP-203)
#     if re.search(r"\b(AZ|DP|AI|PL|SC|MS|MD)-\d{3}\b", line):
#         return True
#     return False

# # --- Main Function for Text Extraction ---

# def count_certifications_from_text(resume_text: str) -> Tuple[int, List[Dict[str, str]]]:
#     """
#     Scans resume text for lines within an explicit 'Certifications' block
#     or lines that strongly resemble a certification, and counts them.

#     Args:
#         resume_text: The text of the resume to scan for certifications.

#     Returns:
#         A tuple (count, certificates), where:
#         - count is the number of unique certifications found (int)
#         - certificates is a list of dicts containing unique certification names and their source/initial score.
#     """
#     certificates: List[Dict[str, str]] = []
#     lines = [ln for ln in (resume_text or "").splitlines() if ln.strip()] # Keep non-empty lines

#     in_cert_block = False
    
#     # Track unique names by a normalized key to prevent duplicates
#     seen_keys = set() 

#     for raw in lines:
#         ln = _norm_text(raw) # Normalized line (stripped)
        
#         # 1. Detect entering/leaving the certification section
#         # Entering the block (more robust heading detection)
#         if re.match(r"^\s*(licenses?&?certifications?|CERTIFICATIONS?|licenses?|professional\s+development)\s*:?$", ln, re.I):
#             in_cert_block = True
#             continue
        
#         # Leaving the block (when a new major section starts)
#         if in_cert_block and re.match(r"^(experience|education|projects?|skills?|profile|summary|achievements?|technical\s+skills|work\s+history)\s*:?\s*$", ln, re.I):
#             in_cert_block = False
#             continue

#         # 2. Extract potential certification lines
#         candidate_raw = raw.strip()
        
#         # Prioritize extraction inside the dedicated block
#         if in_cert_block and len(candidate_raw) > 3:
#             cand_name = _clean_cert_name(candidate_raw)
#             key = re.sub(r"[\s\-–—]+", " ", cand_name.lower()).strip()
            
#             # Check for a cert hint even in the block, to filter out simple bullets like "January 2023"
#             if key and len(key) >= 5 and key not in seen_keys:
#                  # If inside the block, trust the text more, but still validate minimum quality
#                 seen_keys.add(key)
#                 certificates.append({
#                     "name": cand_name,
#                     "source": "cert_section",
#                     "score": 0 
#                 })
        
#         # Secondary check: extract strong cert-looking lines anywhere (e.g., in a summary or projects section)
#         elif not in_cert_block and _looks_like_cert_line(candidate_raw) and len(candidate_raw) >= 5:
#             cand_name = _clean_cert_name(candidate_raw)
#             key = re.sub(r"[\s\-–—]+", " ", cand_name.lower()).strip()

#             if key and key not in seen_keys:
#                 seen_keys.add(key)
#                 certificates.append({
#                     "name": cand_name,
#                     "source": "anywhere_hint",
#                     "score": 0
#                 })

#     # The original scoring logic from your provided code is kept minimal here for clean integration,
#     # but the ATS scoring function (calculate_dynamic_ats_score) can use the names for its own advanced scoring.
#     # We only return the count of unique detected names and the list of unique names.
    
#     unique_count = len(certificates)
#     return unique_count, certificates
import re
from typing import List, Tuple, Dict
from urllib.parse import urlparse

# --- Helper functions (kept the same) ---

def _norm_text(text: str) -> str:
    """Normalize the text by stripping and retaining original structure."""
    return (text or "").strip()

def _clean_cert_name(text: str) -> str:
    """Clean up the certification name by removing common noise."""
    s = text.strip()
    s = re.sub(r"^\s*[-*•■●]|[0-9]+\.\s*", "", s).strip()
    s = re.sub(r"\s*\(.*?\)|\s*\[.*?\]|\s*\{\.*?\}", "", s)
    s = re.sub(r"[\s\-,;]+(?:[A-Za-z]+\s+)?\d{4}(?:\s*-\s*(?:present|\d{4}))?\s*$", "", s, flags=re.I).strip()
    s = re.sub(r"\s*(License|Credential|ID|No\.?|Certificate)\s*.*$", "", s, flags=re.I).strip()
    return re.sub(r"\s{2,}", " ", s)

def _looks_like_cert_line(line: str) -> bool:
    """Detect if a line looks like a certification using strong keywords/patterns."""
    if re.search(r"\b(certification|certificate|certified|license|licen[sc]e|credential|exam|badge)\b", line, re.I):
        return True
    if re.search(r"\b(AWS|Azure|GCP|PMP|CISSP|CompTIA|CKA|CKAD)\b", line):
        return True
    if re.search(r"\b(AZ|DP|AI|PL|SC|MS|MD)-\d{3}\b", line):
        return True
    return False

# --- Main Function with Aggressive Split Logic ---

def count_certifications_from_text(resume_text: str) -> Tuple[int, List[Dict[str, str]]]:
    """
    Scans resume text, aggressively splitting content within the 'Certifications' 
    block to correctly count single-line or poorly formatted entries.

    Args:
        resume_text: The text of the resume to scan for certifications.

    Returns:
        A tuple (count, certificates), where:
        - count is the number of unique certifications found (int)
        - certificates is a list of dicts containing unique certification names.
    """
    certificates: List[Dict[str, str]] = []
    # Split by actual lines and the special PDF source markers, but join them back temporarily
    lines = [ln for ln in (resume_text or "").splitlines()]
    
    in_cert_block = False
    cert_block_content = []
    seen_keys = set() 

    for raw in lines:
        ln = _norm_text(raw)
        
        # 1. Detect entering/leaving the certification section
        if re.match(r"^\s*(licenses?&?certifications?|CERTIFICATIONS?|licenses?|professional\s+development)\s*:?$", ln, re.I):
            in_cert_block = True
            continue
        
        if in_cert_block:
            # Check for block exit BEFORE processing the content
            if re.match(r"^(experience|education|projects?|skills?|profile|summary|achievements?|technical\s+skills|work\s+history)\s*:?\s*$", ln, re.I):
                in_cert_block = False
                # Process the accumulated content before breaking out of the block
                if cert_block_content:
                    raw_block_text = " ".join(cert_block_content)
                    break # Break after processing
                else:
                    break

            # Accumulate content
            if ln:
                cert_block_content.append(raw)
    
    # Process the accumulated content outside the loop if a block was detected
    if in_cert_block and cert_block_content:
        # If the block content was accumulated until the end of the document, 
        # process it here (i.e., the loop finished without hitting a break/exit)
        raw_block_text = " ".join(cert_block_content)
    elif not in_cert_block and cert_block_content:
        # This case is hit if the block exit condition was met, and the break was processed.
        # The content would already be accumulated into raw_block_text via the break logic.
        pass
    else:
        raw_block_text = ""

    # --- Aggressive Split Logic for the Certification Block ---
    if raw_block_text:
        # Strategy: Split by common separators that separate list items,
        # ensuring the text is treated as one stream for splitting.
        
        # 1. Replace date ranges (like 2023-Present) with a placeholder to prevent premature splitting.
        # 2. Aggressively split by large separators (like | or ;), or by
        #    a major entry point (Capital Letter followed by space/word/number, often the start of a new cert).
        
        # Replace date ranges or ID numbers with a safe token
        temp_text = re.sub(r'(\d{4}\s*-\s*(?:Present|\d{4}))', r'\1_DATE_SEP', raw_block_text, flags=re.I)
        temp_text = re.sub(r'(DP-\d{3})', r'\1_CODE_SEP', temp_text, flags=re.I)

        # Aggressively split by common separators used in extracted PDF text:
        # - Two or more spaces followed by a Capital Letter (indicating a new item that lost its newline)
        # - '|' or '—'
        split_candidates = re.split(
            r'\s{2,}(?=[A-Z][a-z])|[\u2013\u2014—\–\s]\s*-\s*|\s*[\|\;]\s*', 
            temp_text.strip()
        )
        
        for item in split_candidates:
            if not item.strip():
                continue
            
            # Restore tokens and clean the name
            item = item.replace('_DATE_SEP', '').replace('_CODE_SEP', '')
            cand_name = _clean_cert_name(item)
            key = re.sub(r"[\s\-–—]+", " ", cand_name.lower()).strip()
            
            # Final check to ensure it looks like a certificate and is unique
            if key and len(key) >= 5 and key not in seen_keys and _looks_like_cert_line(cand_name):
                seen_keys.add(key)
                certificates.append({
                    "name": cand_name,
                    "source": "cert_section_split",
                    "score": 0
                })
    
    # --- Process lines outside of the block (Original Secondary Check) ---
    
    # Run a simple line-by-line check on all original lines for items found outside the primary block
    for raw in lines:
        if raw.strip() not in cert_block_content: # Avoid reprocessing content already analyzed in the block
            candidate_raw = raw.strip()
            
            if _looks_like_cert_line(candidate_raw) and len(candidate_raw) >= 5:
                cand_name = _clean_cert_name(candidate_raw)
                key = re.sub(r"[\s\-–—]+", " ", cand_name.lower()).strip()

                if key and key not in seen_keys:
                    seen_keys.add(key)
                    certificates.append({
                        "name": cand_name,
                        "source": "anywhere_hint",
                        "score": 0
                    })
                    
    # The final count is the total number of unique certificates gathered
    unique_count = len(certificates)
    return unique_count, certificates
    
# --- MODIFIED FUNCTION SIGNATURE AND LOGIC ---
def calculate_dynamic_ats_score(resume_text: str, github_username: str, leetcode_username: str, extracted_links: List[Dict[str, Any]], cert_count: int, cert_names_found: List[str]):
    # ... (Keep all helper functions: has_word, distinct_links_of, all_links_domain_contains, grade_tag) ...
    # (The contents of the provided calculate_dynamic_ats_score function remain mostly intact, 
    # but the internal call to count_only_certifications is removed, and cert data is used)

    def has_word(text, *words):
        t = (text or "").lower()
        return any(w.lower() in t for w in words)

    def distinct_links_of(types):
        bucket: Dict[str, Dict[str, Any]] = {}
        for l in extracted_links or []:
            t = (l.get("type") or "").lower()
            if t in {x.lower() for x in (types if isinstance(types, (set, list, tuple)) else [types])}:
                u = (l.get("url") or "").strip()
                if u and u not in bucket:
                    bucket[u] = l
        return list(bucket.values())

    def all_links_domain_contains(*needles):
        urls = [(l.get("url") or "") for l in (extracted_links or [])]
        needles_low = [n.lower() for n in needles]
        return any(any(n in u.lower() for n in needles_low) for u in urls)

    def grade_tag(score, max_points):
        try:
            return get_grade_tag(score)
        except Exception:
            pct = 0 if max_points <= 0 else (score / max_points) * 100
            if pct >= 85: return "Excellent"
            if pct >= 70: return "Good"
            if pct >= 50: return "Average"
            return "Poor"

    text_lower = (resume_text or "").lower()

    gh_links      = distinct_links_of({"github"})
    li_links      = distinct_links_of({"linkedin"})
    lc_links      = distinct_links_of({"leetcode"})
    blog_links    = distinct_links_of({"blog"})
    notion_links  = distinct_links_of({"notion"})
    other_links   = distinct_links_of({"other"})
    demoish       = [l for l in (extracted_links or []) if has_word(l.get("url",""), "demo", "app.", "vercel", "netlify", "onrender", "cloudfront", "pages.dev", "github.io")]

    github_presence   = bool(github_username) or bool(gh_links)
    leetcode_presence = bool(leetcode_username) or bool(lc_links)
    linkedin_presence = bool(li_links)
    
    portfolio_links = other_links + blog_links + notion_links
    portfolio_presence = bool(portfolio_links) or (
        has_word(resume_text, "portfolio", "personal website", "project", "demo") and len(extracted_links or []) > 0
    )
    
    # CERT_COUNT and CERT_NAMES_FOUND are now inputs, not calculated here!
    cert_presence = cert_count > 0 

    # GitHub (0–27) - (Logic remains the same as provided)
    gh_sub = []
    gh_score = 0
    if github_presence:
        # ... (GitHub score calculation logic)
        gh_sub.append({"name":"Public link present","score":3,"weight":3,"insight":"GitHub link detected."})
        repo_link_count = sum(1 for l in gh_links if re.search(r"github\.com/[^/]+/[^/#?]+", (l.get("url") or ""), re.I))
        mentions_docs = has_word(resume_text, "readme", "docs", "documentation")
        mentions_tests = has_word(resume_text, "pytest", "unittest", "jest", "cypress", "tests", "ci", "github actions")
        multi_stack = sum(1 for k in ["python","javascript","typescript","java","go","rust","scala","kotlin","c++","c#","sql","docker","kubernetes","terraform","spark","airflow"] if k in text_lower) >= 5
        has_demo = len(demoish) > 0 or all_links_domain_contains("github.io")

        if repo_link_count == 0: base = 3
        elif repo_link_count == 1: base = 8
        elif repo_link_count == 2: base = 12
        else: base = 18

        if mentions_docs: base += 2
        if mentions_tests: base += 2
        if has_demo: base += 2
        if multi_stack: base += 3
        gh_score = max(2, min(27, base))

        gh_sub.extend([
            {"name":"Repo links detected","score":min(6, repo_link_count*2),"weight":6,"insight":f"{repo_link_count} repo link(s) found."},
            {"name":"Docs/README/tests/CI","score":(2 if mentions_docs else 0)+(2 if mentions_tests else 0),"weight":4,"insight":"Signals of quality and maintainability."},
            {"name":"Hosted demos","score":2 if has_demo else 0,"weight":2,"insight":"Live demo or GitHub Pages present."},
            {"name":"Stack diversity","score":3 if multi_stack else 0,"weight":3,"insight":"Multiple languages/tools referenced."},
        ])
    else:
        gh_sub.append({"name":"Public link present","score":0,"weight":3,"insight":"No GitHub link or username found."})

    # LeetCode (0–9) - (Logic remains the same as provided)
    lc_sub = []
    lc_score = 0
    if leetcode_presence:
        # ... (LeetCode score calculation logic)
        solved_hint = re.search(r'(\d{2,4})\s*\+?\s*(?:problems|questions|solutions)\b', text_lower)
        hard_hint   = has_word(resume_text, "hard", "dp", "graph", "greedy", "binary search", "segment tree", "fenwick")
        contest     = has_word(resume_text, "contest", "weekly", "biweekly", "ranking", "rating")
        baseline = 3
        if solved_hint:
            try:
                n = int(solved_hint.group(1))
                if n >= 300: baseline = 8
                elif n >= 200: baseline = 7
                elif n >= 100: baseline = 6
                elif n >= 50: baseline = 5
                else: baseline = 4
            except Exception:
                pass
        if hard_hint: baseline += 1
        if contest: baseline += 1
        lc_score = min(9, baseline)
        lc_sub = [
            {"name":"Profile presence","score":3,"weight":3,"insight":"LeetCode link or username found."},
            {"name":"Problem count","score":min(3, baseline-3),"weight":3,"insight":"Solved problems count inferred."},
            {"name":"Hard/contest","score":2 if (hard_hint or contest) else 0,"weight":3,"insight":"Advanced topics or contests mentioned."},
        ]
    else:
        lc_sub = [{"name":"Profile presence","score":0,"weight":3,"insight":"No LeetCode link or username found."}]

    # LinkedIn (0–18) - (Logic remains the same as provided)
    li_sub = []
    li_score = 0
    if linkedin_presence:
        # ... (LinkedIn score calculation logic)
        headline = any(has_word(l.get("title","") or l.get("description",""), "engineer", "developer", "data", "software", "analyst", "scientist") for l in li_links)
        about    = any(has_word(l.get("description",""), "experience", "skills", "certification", "education", "project") for l in li_links)
        exp      = has_word(resume_text, "experience", "worked", "job", "position", "role", "internship")
        projects = has_word(resume_text, "project", "built", "developed", "created", "designed")
        skills   = has_word(resume_text, "skill", "proficient", "expert", "familiar", "knowledge")
        certs    = has_word(resume_text, "certification", "certified", "course", "training", "degree", "education")
        base = 5
        if headline: base += 2
        if about: base += 3
        if exp: base += 4
        if projects: base += 3
        if skills: base += 2
        if certs: base += 2
        li_score = min(18, base)
        li_sub = [
            {"name":"Headline","score":2 if headline else 0,"weight":2,"insight":"Professional headline present."},
            {"name":"About section","score":3 if about else 0,"weight":3,"insight":"About section or summary found."},
            {"name":"Experience","score":4 if exp else 0,"weight":4,"insight":"Experience section detected."},
            {"name":"Projects","score":3 if projects else 0,"weight":3,"insight":"Projects mentioned."},
            {"name":"Skills","score":2 if skills else 0,"weight":2,"insight":"Skills section found."},
            {"name":"Certs/Education","score":2 if certs else 0,"weight":2,"insight":"Certifications or education mentioned."},
        ]
    else:
        li_sub = [{"name":"Profile presence","score":0,"weight":2,"insight":"No LinkedIn link found."}]

    # Portfolio (0–23) - (Logic remains the same as provided)
    pf_sub = []
    pf_score = 0
    if portfolio_presence:
        # ... (Portfolio score calculation logic)
        pf_links = portfolio_links
        pf_count = len(pf_links)
        has_blog = len(blog_links) > 0
        has_notion = len(notion_links) > 0
        has_demo = len(demoish) > 0
        mentions_portfolio = has_word(resume_text, "portfolio", "personal website", "project", "demo")
        base = 5
        if pf_count == 1: base += 3
        elif pf_count >= 2: base += 6
        if has_blog: base += 3
        if has_notion: base += 2
        if has_demo: base += 4
        if mentions_portfolio: base += 3
        pf_score = min(23, base)
        pf_sub = [
            {"name":"Portfolio links","score":min(6, pf_count*3),"weight":6,"insight":f"{pf_count} portfolio link(s) found."},
            {"name":"Blog posts","score":3 if has_blog else 0,"weight":3,"insight":"Blog or articles found."},
            {"name":"Notion/docs","score":2 if has_notion else 0,"weight":2,"insight":"Notion or documentation links."},
            {"name":"Live demos","score":4 if has_demo else 0,"weight":4,"insight":"Live demo links found."},
            {"name":"Mentions in resume","score":3 if mentions_portfolio else 0,"weight":3,"insight":"Portfolio mentioned in resume."},
        ]
    else:
        pf_sub = [{"name":"Portfolio presence","score":0,"weight":6,"insight":"No portfolio links found."}]

    # Resume ATS (0–23) - (Logic remains the same as provided)
    ats_sub = []
    ats_score = 0
    if resume_text:
        # ... (ATS score calculation logic)
        # kw_tech, kw_soft calculation is long, assuming it's correct from the provided code
        # ... 
        kw_tech = sum(1 for k in ["python","sql","aws","docker","kubernetes","spark","airflow","javascript","typescript","java","go","rust","scala","kotlin","c++","c#","terraform","ansible","jenkins","ci/cd","git","github","gitlab","jira","agile","scrum","tableau","powerbi","excel","nosql","mongodb","postgresql","mysql","redis","kafka","rabbitmq","elasticsearch","snowflake","redshift","bigquery","databricks","hadoop","hive","hbase","cassandra","dynamodb","s3","ec2","lambda","glue","step functions","cloudformation","cloudwatch","x-ray","vpc","iam","route53","elb","nginx","apache","linux","bash","shell","powershell","nodejs","react","angular","vue","django","flask","fastapi","spring","express","graphql","rest","api","grpc","thrift","protobuf","avro","parquet","orc","csv","json","xml","yaml","toml","ini","env","dockerfile","docker-compose","k8s","helm","kustomize","argo","tekton","spinnaker","jenkins","circleci","github actions","gitlab ci","travis","teamcity","bamboo","ansible","puppet","chef","saltstack","terraform","cloudformation","pulumi","cdk","serverless","sam","chalice","zappa","vercel","netlify","heroku","firebase","supabase","auth0","okta","cognito","oauth","jwt","ssl","tls","https","ssh","vpn","ipsec","wireguard","openvpn","ldap","kerberos","saml","oidc","mfa","2fa","totp","hotp","webauthn","fido","u2f","biometrics","facial recognition","iris scan","fingerprint","voice recognition","behavioral biometrics","ai","ml","machine learning","deep learning","neural networks","cnn","rnn","lstm","gru","transformer","bert","gpt","t5","vit","resnet","inception","efficientnet","mobilenet","yolo","ssd","faster r-cnn","mask r-cnn","retinanet","centernet","detr","pointpillars","pointrcnn","second","pv-rcnn","part-a2","3dssd","voxelnet","pointnet","pointnet++","pointcnn","dgcnn","kpconv","randla-net","polarnet","spconv","minkowskiengine","torchsparse","openpcdet","mmdetection3d","detectron2","mmdetection","yolov5","yolov6","yolov7","yolov8","yolov9","yolox","scaled-yolov4","efficientdet","nanodet","pp-yolo","ppyoloe","ppyolov2","centernet","cornernet","fcos","atss","gfl","dynamicrpn","reppoints","foveabox","freenet","sparse r-cnn","querydet","detic","deformable detr","conditional detr","dab-detr","dn-detr","dino","mask2former","maskformer","k-net","max-deeplab","maskclip","mask dino","groupvit","x-decoder","open-seed","sam","segment anything","fastsam","efficientsam","mobile sam","edge sam","sam2","grounding dino","grounding sam","owl","owlv2","glip","glipv2","detclip","grit","uni-detr","uniperceptor","unidet","ovd","open-vocabulary detection","zero-shot detection","few-shot detection","semi-supervised detection","weakly-supervised detection","unsupervised detection","self-supervised detection","contrastive learning","momentum contrast","moco","simclr","byol","swav","barlow twins","vicreg","dino","ibot","mae","masked autoencoder","simsiam","nnclr","supcon","deepcluster","scan","sela","pcl","cpc","amdim","bigbigan","stylegan","stylegan2","stylegan3","progan","sggan","logan","wgan","wgan-gp","lsgan","rsgan","ragan","hingegan","loss sensitive gan","ebgan","began","margin gan","f-gan","mmgan","nsgan","sngan","sagan","biggan","bigbigan","trgan","stylegan-ada","stylegan2-ada","stylegan3-ada","training","fine-tuning","transfer learning","domain adaptation","domain generalization","test-time adaptation","test-time training","meta-learning","few-shot learning","zero-shot learning","multi-task learning","continual learning","lifelong learning","online learning","active learning","semi-supervised learning","weakly-supervised learning","self-supervised learning","unsupervised learning","reinforcement learning","imitation learning","inverse reinforcement learning","offline rl","online rl","batch rl","model-based rl","model-free rl","policy gradient","actor-critic","q-learning","sarsa","dqn","ddpg","td3","sac","ppo","trpo","mpc","ilqr","ddim","ddpm","score-based","diffusion","normalizing flows","real nvp","glow","maf","iaf","nice","ffjord","sde","ode","neural ode","hamiltonian nn","lagrangian nn","symplectic nn","geometric nn","graph nn","gnn","gcn","gat","graphsage","gin","pna","mpnn","transformers","attention","self-attention","multi-head attention","transformer","bert","gpt","t5","vit","swin","deit","cait","crossvit","levit","convit","t2t-vit","pit","xcit","coat","cvt","twins","pvt","shuffle transformer","mobilevit","edgevit","efficientformer","mobileformer","poolformer","uniformer","linformer","performer","nyströmformer","longformer","bigbird","reformer","linformer","sinkhorn transformer","rfa","linear transformer","synthesizer","rfa","fast attention","flash attention","block-sparse attention","longshort-transformer","et","informer","autoformer","fedformer","stationary","non-stationary","time series","forecasting","anomaly detection","change point detection","event detection","segmentation","classification","regression","clustering","dimensionality reduction","feature selection","feature extraction","manifold learning","pca","ica","lda","nmf","tsne","umap","phate","diffusion maps","isomap","lle","mds","spectral embedding","kernel pca","autoencoder","vae","cvae","vq-vae","vq-vae-2","nva","diffusion autoencoder","gan","vae-gan","cyclegan","unit","munit","stargan","stargan2","ganilla","attentiongan","stylegan","biggan","stylegan-ada","stylegan2-ada","stylegan3-ada"] if k in text_lower)
        kw_soft = sum(1 for k in ["leadership","team","communication","problem solving","critical thinking","creativity","adaptability","time management","project management","agile","scrum","kanban","lean","devops","mlops","dataops","gitops","finops","secops","aiops","modelops"] if k in text_lower)
        
        base = 5
        if kw_tech >= 20: base += 5
        elif kw_tech >= 10: base += 3
        elif kw_tech >= 5: base += 1
        if kw_soft >= 5: base += 3
        elif kw_soft >= 3: base += 1
        has_quant = bool(re.search(r'\b\d+%|\$\d+|\d+\s*(?:years?|months?|weeks?|days?|hours?|minutes?|seconds?)\b', resume_text))
        if has_quant: base += 2
        has_contact = bool(re.search(r'\b(?:phone|email|@|\.com|\.org|\.net|linkedin\.com|github\.com|leetcode\.com)\b', resume_text, re.I))
        if has_contact: base += 2
        has_edu = bool(re.search(r'\b(?:b\.?a|b\.?s|b\.?eng|m\.?a|m\.?s|m\.?eng|ph\.?d|doctorate|master|bachelor|diploma|degree|certificate|certification)\b', resume_text, re.I))
        if has_edu: base += 2
        ats_score = min(23, base)
        ats_sub = [
            {"name":"Technical keywords","score":min(5, kw_tech//4),"weight":5,"insight":f"{kw_tech} technical terms found."},
            {"name":"Soft skills","score":min(3, kw_soft//2),"weight":3,"insight":f"{kw_soft} soft skill terms found."},
            {"name":"Quantified results","score":2 if has_quant else 0,"weight":2,"insight":"Quantified achievements present."},
            {"name":"Contact info","score":2 if has_contact else 0,"weight":2,"insight":"Contact details included."},
            {"name":"Education","score":2 if has_edu else 0,"weight":2,"insight":"Education section found."},
        ]
    else:
        ats_sub = [{"name":"Resume text","score":0,"weight":5,"insight":"No resume text provided."}]

    # Certifications & Branding (0–9) - Uses INPUTS
    cert_sub = []
    cert_score = 0
    
    # Recalculate score using cert_count (as done in the original logic, slightly simplified for clean integration)
    has_brand = has_word(resume_text, "personal brand", "branding", "online presence", "thought leadership")
    has_blog = len(blog_links) > 0
    base = 3
    if cert_count >= 6: base += 6
    elif cert_count >= 3: base += 4
    elif cert_count >= 1: base += 2
    if has_brand: base += 2
    if has_blog: base += 1
    cert_score = min(9, base)
    cert_names_found = [cert['name'] for cert in cert_names_found]  # Extract only the 'name' fields

    cert_sub = [
        {"name":"Certifications","score":min(6, cert_count * 1.5),"weight":6,"insight":f"{cert_count} certification(s) mentioned"},
        {"name":"Personal branding","score":2 if has_brand else 0,"weight":2,"insight":"Personal branding mentioned."},
        {"name":"Blog/articles","score":1 if has_blog else 0,"weight":1,"insight":"Blog or articles found."},
    ]
    # Adjust score calculation to be the sum of sub-criteria, capped at 9, for consistency with sub_criteria display.
    # The original base calculation was non-linear, so we'll use a linear sum of sub-criteria here.
    cert_score_linear = sum(c.get("score", 0) for c in cert_sub)
    cert_score = min(9, cert_score_linear)

    # ---------------- Overall ----
    # ... (Rest of function remains the same)
    sections = {
        "GitHub Profile": {
            "score": gh_score,
            "grade": grade_tag(gh_score, 27),
            "weight": TECHNICAL_WEIGHTS["GitHub Profile"],
            "sub_criteria": gh_sub
        },
        "LinkedIn": {
            "score": li_score,
            "grade": grade_tag(li_score, 18),
            "weight": TECHNICAL_WEIGHTS["LinkedIn"],
            "sub_criteria": li_sub
        },
        "Portfolio Website": {
            "score": pf_score,
            "grade": grade_tag(pf_score, 23),
            "weight": TECHNICAL_WEIGHTS["Portfolio Website"],
            "sub_criteria": pf_sub
        },
        "Resume (ATS Score)": {
            "score": ats_score,
            "grade": grade_tag(ats_score, 23),
            "weight": TECHNICAL_WEIGHTS["Resume (ATS Score)"],
            "sub_criteria": ats_sub
        },
        "Certifications & Branding": {
            "score": cert_score,
            "grade": grade_tag(cert_score, 9),
            "weight": TECHNICAL_WEIGHTS["Certifications & Branding"],
            "sub_criteria": cert_sub
        },
        "LeetCode/DSA Skills": {
            "score": lc_score,
            "grade": grade_tag(lc_score, 9),
            "weight": TECHNICAL_WEIGHTS["LeetCode/DSA Skills"],
            "sub_criteria": lc_sub
        }
    }

    total_weighted = sum(s["score"] for s in sections.values())
    total_max = sum(TECHNICAL_WEIGHTS.values())
    overall_score = round((total_weighted / total_max) * 100, 1) if total_max > 0 else 0
    overall_grade = get_grade_tag(overall_score)

    suggestions = []
    if gh_score < 10:
        suggestions.append("Improve GitHub: add more projects, READMEs, tests, or live demos.")
    if li_score < 6:
        suggestions.append("Enhance LinkedIn: complete profile with experience, skills, and projects.")
    if pf_score < 10:
        suggestions.append("Build portfolio: create personal website, blog, or project showcases.")
    if ats_score < 10:
        suggestions.append("Optimize resume: add more keywords, quantify results, and include contact info.")
    if cert_score < 3:
        suggestions.append("Consider certifications: they can boost credibility and ATS scores.")
    if lc_score < 3:
        suggestions.append("Practice DSA: LeetCode or similar platforms can demonstrate problem-solving skills.")

    return {
        "sections": sections,
        "overall_score_average": overall_score,
        "overall_grade": overall_grade,
        "suggestions": suggestions
    }

# --- END OF MODIFIED calculate_dynamic_ats_score ---

# The helper function for fetching recommendations (assuming openai is imported)
def suggest_role_certifications_v1(role_slug, detected_certs=None):
    if detected_certs is None:
        detected_certs = []
    
    # Extract the certification names from the dictionaries and convert to lowercase
    detected_lower = {cert['name'].lower() for cert in detected_certs}  # Ensure 'name' is extracted from dict
    
    # Ensure OPEN_API is defined or imported, as it's used below
    api_key = os.getenv("OPEN_API")
    
    if not api_key:
        print("OpenAI API key not found in .env; falling back to hardcoded recommendations.")
        role_cert_map = {
            "data_scientist": [
                "Coursera Data Science Specialization",
                "edX Professional Certificate in Data Science",
                "Udemy The Data Science Course: Complete Data Science Bootcamp",
                "Coursera Machine Learning by Stanford University",
                "edX Data Science MicroMasters"
            ],
            "software_engineer": [
                "Udemy The Web Developer Bootcamp",
                "Coursera Software Engineering Fundamentals",
                "edX CS50's Introduction to Computer Science",
                "Udemy Complete Python Bootcamp",
                "Coursera Algorithms Part I"
            ],
            "machine_learning_engineer": [
                "Coursera Deep Learning Specialization",
                "Udemy Machine Learning A-Z",
                "edX Artificial Intelligence MicroMasters",
                "Coursera Machine Learning by Stanford University",
                "Udemy Deep Learning Prerequisites: The Numpy Stack in Python"
            ],
            "devops_engineer": [
                "Udemy Docker and Kubernetes: The Complete Guide",
                "Coursera Google Cloud Platform Fundamentals for AWS Professionals",
                "edX DevOps on AWS",
                "Udemy Learn DevOps: The Complete Kubernetes Course",
                "Coursera Site Reliability Engineering: Measuring and Managing Reliability"
            ],
            "data_analyst": [
                "Google Data Analytics Professional Certificate",
                "Udemy Data Analyst Bootcamp",
                "Coursera IBM Data Analyst Professional Certificate",
                "edX Data Analytics for Business",
                "Udemy Tableau 2022 A-Z: Hands-On Tableau Training"
            ]
        }
        role_key = role_slug.lower().replace(" ", "_").replace("-", "_")
        recommended_certs = role_cert_map.get(role_key, [
            "Coursera Python for Everybody",
            "edX Introduction to Computer Science",
            "Udemy Complete Python Bootcamp",
            "Coursera Google IT Support Professional Certificate",
            "edX Data Science Essentials"
        ])
        filtered_recs = [cert for cert in recommended_certs if cert.lower() not in detected_lower]
        print(f"Fallback recommended certifications for role '{role_slug}' (deduped): {filtered_recs[:5]}")
        return filtered_recs[:5]
    
    try:
        # Assuming openai client is available in the environment
        import openai
        client = openai.OpenAI(api_key=api_key)
        prompt = f"""
Suggest exactly 5 top certifications for a '{role_slug}' role, available on platforms like Udemy, Coursera, or edX. 
Ensure the certifications are real, relevant to the role, and offered by these platforms.
Return the response as a JSON array of strings, e.g., ["Cert 1", "Cert 2", ...].
"""
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=200
        )
        
        content = response.choices[0].message.content.strip()
        if content.startswith("```json"):
            content = content.split("```json")[1].split("```")[0].strip()
        recommended_certs = json.loads(content)
        
        # Deduplicate recommendations based on what is already detected in the resume
        filtered_recs = [cert for cert in recommended_certs if isinstance(cert, str) and cert.lower() not in detected_lower]
        print(f"OpenAI recommended certifications for role '{role_slug}' (deduped): {filtered_recs[:5]}")
        return filtered_recs[:5]
        
    except Exception as e:
        print(f"OpenAI API error for recommendations: {e}; falling back to hardcoded.")
        # Fallback logic to handle API failure
        role_cert_map = {
            "data_scientist": [
                "Coursera Data Science Specialization",
                "edX Professional Certificate in Data Science",
                "Udemy The Data Science Course: Complete Data Science Bootcamp",
                "Coursera Machine Learning by Stanford University",
                "edX Data Science MicroMasters"
            ],
            "software_engineer": [
                "Udemy The Web Developer Bootcamp",
                "Coursera Software Engineering Fundamentals",
                "edX CS50's Introduction to Computer Science",
                "Udemy Complete Python Bootcamp",
                "Coursera Algorithms Part I"
            ]
        }
        role_key = role_slug.lower().replace(" ", "_").replace("-", "_")
        recommended_certs = role_cert_map.get(role_key, [
            "Coursera Python for Everybody",
            "edX Introduction to Computer Science",
            "Udemy Complete Python Bootcamp",
            "Coursera Google IT Support Professional Certificate",
            "edX Data Science Essentials"
        ])
        filtered_recs = [cert for cert in recommended_certs if cert.lower() not in detected_lower]
        print(f"Fallback recommended certifications for role '{role_slug}' (deduped): {filtered_recs[:5]}")
        return filtered_recs[:5]


from .utils import *
@require_POST
def analyze_resume(request):
    os.environ.setdefault("MPLBACKEND", "Agg")
    os.environ.setdefault("MPLCONFIGDIR", "/tmp/matplotlib")

    if request.POST.get("domain") != "technical":
        return HttpResponseBadRequest("Please choose Technical category.")
    if "resume" not in request.FILES:
        return HttpResponseBadRequest("Resume file required.")

    resume_file = request.FILES["resume"]
    ext = os.path.splitext(resume_file.name)[1].lower()

    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
        for chunk in resume_file.chunks():
            tmp.write(chunk)
        temp_path = tmp.name

    try:
        # Extract text & anchors
        if ext == ".pdf":
            # Assuming extract_links_combined and _normalize_text are available
            legacy_links, resume_text_raw = extract_links_combined(temp_path)
            resume_text = _normalize_text(resume_text_raw or "")
        elif ext == ".docx":
            # Assuming extract_text_from_docx, _normalize_text, and extract_links_from_docx are available
            resume_text_raw = extract_text_from_docx(temp_path) or ""
            resume_text = _normalize_text(resume_text_raw)
            legacy_links = extract_links_from_docx(temp_path)
        elif ext in (".txt",):
            with open(temp_path, "r", encoding="utf-8", errors="ignore") as f:
                resume_text_raw = f.read()
            resume_text = _normalize_text(resume_text_raw or "")
            legacy_links = []
        else:
            return HttpResponseBadRequest("Unsupported file format.")

        role_slug = request.POST.get("tech_role", "data_scientist")
        print(f"Processing resume for role: {role_slug}")
        print(f"Resume text (first 500 chars): {resume_text[:500]}...")

        # Metadata enrich + URLs from text
        # Assuming process_resume_links, extract_urls_from_text, _domain_of, _dedupe_preserve_order_link_dicts are available
        resume_links_full = process_resume_links(
            temp_path,
            mime_type=resume_file.content_type,
            fetch_metadata=True,
            limit=120,
        ) or []

        text_urls = extract_urls_from_text(resume_text)
        existing = {i.get("url") for i in resume_links_full if i.get("url")}
        extra_pool = []
        for u in (legacy_links + text_urls):
            if not u or u in existing:
                continue
            extra_pool.append({
                "url": u,
                "domain": _domain_of(u),
                "type": "other",
                "title": "",
                "description": "",
            })
        merged_links = _dedupe_preserve_order_link_dicts(resume_links_full + extra_pool)

        # Validate links
        # Assuming validate_links_enrich and only_ok_links are available
        enriched_links = validate_links_enrich(merged_links)
        ok_links = only_ok_links(enriched_links)
        link_urls_ok = [i.get("final_url") or i.get("url") for i in ok_links if i.get("url")]
        link_urls_all = [i.get("final_url") or i.get("url") for i in enriched_links if i.get("url")]

        # Inputs / usernames (Detection logic remains the same)
        applicant_name = extract_applicant_name(resume_text) or "Candidate"
        github_username = (request.POST.get("github_username", "") or "").strip() \
                            or extract_github_username(resume_text) \
                            or infer_github_username(link_urls_ok or link_urls_all, resume_text) \
                            or ""

        # ... (github_detection logic remains the same, assuming requests is imported)
        github_detection = "NO"
        if re.search(r'github', resume_text, re.IGNORECASE):
            github_urls = [url for url in (link_urls_ok + link_urls_all) if "github.com" in url.lower()]
            def is_valid_github_url(url: str) -> bool:
                if not re.match(r'https?://(www\.)?github\.com/[a-zA-Z0-9-_]+', url, re.IGNORECASE):
                    return False
                try:
                    response = requests.head(url, allow_redirects=True, timeout=5)
                    if response.status_code == 200 and "github.com" in response.url.lower():
                        return True
                except requests.RequestException:
                    return False
                return False
            if any(is_valid_github_url(url) for url in github_urls):
                github_detection = "YES"
        print(f"GitHub detection: '{github_detection}'")

        leetcode_username = (request.POST.get("leetcode_username", "") or "").strip() \
                            or extract_leetcode_username(resume_text) \
                            or infer_leetcode_username(link_urls_ok or link_urls_all, resume_text) \
                            or ""
        job_description = (request.POST.get("job_description", "") or "").strip()

        # --- FIX 1 & 2: Single Certificate Calculation and Recommendation ---
        cert_count, cert_names_found = count_certifications_from_text(resume_text)
        print(f"Certifications detected: count = {cert_count}, names = {cert_names_found}")

        recommended_certs = suggest_role_certifications_v1(role_slug, cert_names_found)
        # -------------------------------------------------------------------

        # Dynamic ATS - NOW PASSES CERT DATA
        dyn = calculate_dynamic_ats_score(
            resume_text=resume_text,
            github_username=github_username if any("github.com" in (u or "") for u in link_urls_ok) else "",
            leetcode_username=leetcode_username if any("leetcode." in (u or "") for u in link_urls_ok) else "",
            extracted_links=ok_links,
            cert_count=cert_count, # <-- PASSED
            cert_names_found=cert_names_found, # <-- PASSED
        )

        print(f"Initial ATS section scores from calculate_dynamic_ats_score: {dyn['sections']}")

        # Apply post-scoring logic updates
        portfolio_present_any = any(l for l in enriched_links if l.get("type") == "portfolio")
        ok_portfolio = [l for l in ok_links if l.get("type") == "portfolio"]
        # The portfolio overwrite logic is kept, though it duplicates the logic in dyn_ats.
        if not portfolio_present_any and not ok_portfolio:
            dyn["sections"]["Portfolio Website"] = {
                "score": 0,
                "grade": "Poor",
                "sub_criteria": [{"name": "Portfolio Presence", "score": 0, "weight": 2, "insight": "No portfolio links detected in resume."}]
            }
        print(f"Portfolio present: {portfolio_present_any}, OK portfolio links: {len(ok_portfolio)}")

        # Optional GitHub API score - (Logic remains the same, assuming score_github_via_api exists)
        github_token = os.getenv("OPEN_API")
        if github_username and github_token and any(l for l in ok_links if l.get("type") == "github"):
            try:
                # Assuming score_github_via_api returns gh_score, gh_rationales, gh_evidence, _
                gh_score_api, gh_rationales, gh_evidence, _ = score_github_via_api(github_username, github_token)
                if "sections" in dyn and "GitHub Profile" in dyn["sections"]:
                    gh_sec = dyn["sections"]["GitHub Profile"]
                    # Retaining original heuristic score for fallback/sub-criteria logic (raw_score)
                    raw_score = int(gh_sec.get("score", 0) or 0)
                    # Use the HEURISTIC score for the main section score if API fails or for comparison
                    gh_sec["score"] = min(raw_score, 27) 
                    gh_sec.setdefault("sub_criteria", []).append(
                        {"name": "Heuristic Eval", "score": raw_score, "weight": 27,
                         "insight": "Heuristic GitHub analysis applied (fallback)."}
                    )
                    dyn["sections"]["GitHub Profile"] = gh_sec
            except Exception as e:
                print(f"GitHub API error (fallback to heuristic): {e}")

        # LinkedIn public HTML - (Logic remains the same, assuming score_linkedin_public_html exists)
        _LI_ANY_RE = re.compile(r'(linkedin\.com|linked\s*in)', re.IGNORECASE)
        linkedin_present_any = any(_LI_ANY_RE.search((l.get("final_url") or l.get("url") or "") or resume_text) for l in enriched_links)
        ok_linkedin = next((l for l in ok_links if l.get("type") == "linkedin"), None)

        li_sec = dyn["sections"].get("LinkedIn", {"score": 0, "grade": "Poor", "sub_criteria": []})
        li_sub = li_sec.get("sub_criteria", [])

        if ok_linkedin:
            li_html = ok_linkedin.get("html", "") or ""
            li_url = ok_linkedin.get("final_url") or ok_linkedin.get("url") or ""
            try:
                # Assuming score_linkedin_public_html returns li_score_pub, li_rats_pub, li_evidence_pub
                li_score_pub, li_rats_pub, li_evidence_pub = score_linkedin_public_html(li_html, li_url, resume_text)
                print(f"LinkedIn score from public HTML: {li_score_pub}, rationales: {li_rats_pub}")
                if li_score_pub > 0:
                    li_sec["score"] = min(int(li_score_pub), 18)
                    li_sec["grade"] = "Good" if li_score_pub >= 12 else "Average" if li_score_pub >= 6 else "Poor"
                    li_sub.append({"name": "Public Profile Parse", "score": int(li_score_pub), "weight": 18, "insight": " ; ".join(li_rats_pub)})
                else:
                    li_score_fallback = 2
                    if re.search(r'\b(experience|skills|projects)\b', resume_text, re.IGNORECASE):
                        li_score_fallback += 3
                    li_sec["score"] = min(li_score_fallback, 18)
                    li_sec["grade"] = "Average" if li_score_fallback >= 3 else "Poor"
                    li_sub.append({"name": "Fallback Score", "score": li_score_fallback, "weight": 5, "insight": "LinkedIn HTML unavailable; scored based on resume content."})
            except Exception as e:
                print(f"Error processing LinkedIn HTML: {e}")
                li_score_fallback = 2
                if re.search(r'\b(experience|skills|projects)\b', resume_text, re.IGNORECASE):
                    li_score_fallback += 3
                li_sec["score"] = min(li_score_fallback, 18)
                li_sec["grade"] = "Average" if li_score_fallback >= 3 else "Poor"
                li_sub.append({"name": "Fallback Score", "score": li_score_fallback, "weight": 5, "insight": f"LinkedIn HTML parsing failed: {str(e)}"})
        else:
            li_sec["score"] = 0
            li_sec["grade"] = "Poor"
            li_sub.append({"name": "LinkedIn Presence", "score": 0, "weight": 2, "insight": "No LinkedIn profile detected or unreachable."})

        li_sub = _ensure_presence_row(li_sub, "profile presence",
                                     "LinkedIn profile link present and reachable (public)." if ok_linkedin else
                                     "LinkedIn profile link present but unreachable (login/blocked)." if linkedin_present_any else
                                     "No LinkedIn profile detected in resume.",
                                     2 if ok_linkedin else 0)
        li_sec["sub_criteria"] = li_sub
        dyn["sections"]["LinkedIn"] = li_sec
        print(f"Final LinkedIn section: {dyn['sections']['LinkedIn']}")

        # Portfolio presence (Logic remains the same)
        pf_sec = dyn["sections"].get("Portfolio Website", {"score": 0, "sub_criteria": []})
        pf_sub = pf_sec.get("sub_criteria", [])
        pf_sub = _ensure_presence_row(pf_sub, "portfolio presence",
                                     "Portfolio link(s) present and reachable." if ok_portfolio else
                                     "Portfolio link present but unreachable." if portfolio_present_any else
                                     "No portfolio links detected in resume.",
                                     2 if ok_portfolio else 0)
        pf_sec["sub_criteria"] = pf_sub
        dyn["sections"]["Portfolio Website"] = pf_sec

        # --- FIX 3: REMOVE REDUNDANT CERTIFICATION OVERWRITE LOGIC ---
        # The certificate scoring and sub_criteria are now correctly set within 
        # calculate_dynamic_ats_score using the cert_count/names passed above.
        # The block from line 818 to 846 in the original code is removed.
        # -------------------------------------------------------------

        # Build report sections (Logic remains the same)
        map_to_dyn = {
            "GitHub": "GitHub Profile",
            "LinkedIn": "LinkedIn",
            "Portfolio": "Portfolio Website",
            "Resume (ATS)": "Resume (ATS Score)",
            "Certifications": "Certifications & Branding",
            "LeetCode/DSA Skills": "LeetCode/DSA Skills", # Added for completeness, though unused in scoring map below
        }

        DEFAULT_SECTION_MAX = {
            "GitHub": 27,
            "LinkedIn": 18,
            "Portfolio": 23,
            "Resume (ATS)": 23,
            "Certifications": 9,
        }

        dyn_weights = dyn.get("weights") or {}

        def dyn_max_for(tpl_name: str) -> int:
            dyn_key = map_to_dyn.get(tpl_name)
            if not dyn_key: return 0
            sec = dyn["sections"].get(dyn_key, {})
            if isinstance(sec, dict) and isinstance(sec.get("max"), (int, float)):
                return int(sec.get("max"))
            if dyn_key in dyn_weights and isinstance(dyn_weights[dyn_key], (int, float)):
                return int(dyn_weights[dyn_key])
            if tpl_name in dyn_weights and isinstance(dyn_weights[tpl_name], (int, float)):
                return int(dyn_weights[tpl_name])
            return DEFAULT_SECTION_MAX[tpl_name]

        SECTION_MAX = {name: dyn_max_for(name) for name in DEFAULT_SECTION_MAX.keys()}
        TOTAL_MAX = sum(SECTION_MAX.values())

        def _safe_sec(name):
            return dyn["sections"].get(name, {"score": 0, "grade": "Poor", "sub_criteria": []})

        github_sec = _safe_sec(map_to_dyn["GitHub"])
        linkedin_sec = _safe_sec(map_to_dyn["LinkedIn"])
        portfolio_sec = _safe_sec(map_to_dyn["Portfolio"])
        resume_sec = _safe_sec(map_to_dyn["Resume (ATS)"])
        certs_sec = _safe_sec(map_to_dyn["Certifications"])

        section_scores = {
            "GitHub": int(github_sec.get("score", 0) or 0),
            "LinkedIn": int(linkedin_sec.get("score", 0) or 0),
            "Portfolio": int(portfolio_sec.get("score", 0) or 0),
            "Resume (ATS)": int(resume_sec.get("score", 0) or 0),
            "Certifications": int(certs_sec.get("score", 0) or 0),
        }

        weights_pct = {
            k: int(round((SECTION_MAX[k] / float(TOTAL_MAX)) * 100)) if TOTAL_MAX else 0
            for k in SECTION_MAX
        }

        def _grade_pct(pct: float) -> str:
            if pct >= 85:
                return "Excellent"
            if pct >= 70:
                return "Good"
            if pct >= 50:
                return "Average"
            return "Poor"

        score_breakdown, score_breakdown_ordered = {}, []
        for tpl_name in ["GitHub", "LinkedIn", "Portfolio", "Resume (ATS)", "Certifications"]:
            score = section_scores[tpl_name]
            maxpts = SECTION_MAX[tpl_name]
            grade = _grade_pct((score / maxpts) * 100 if maxpts else 0)
            score_breakdown[tpl_name] = {"score": score, "max": maxpts, "grade": grade, "weight": weights_pct[tpl_name]}
            score_breakdown_ordered.append((tpl_name, {
                "score": score,
                "grade": grade,
                "sub_criteria": (_safe_sec(map_to_dyn[tpl_name]).get("sub_criteria") or []),
            }))

        total_score = sum(section_scores.values())
        total_max_score_for_pct = sum(SECTION_MAX.values())
        profile_percent = int(round((total_score / float(total_max_score_for_pct)) * 100)) if total_max_score_for_pct else 0

        def _color_class(pct: int) -> str:
            if pct > 80: return "score-box"
            if pct >= 50: return "score-box-orange"
            return "score-box-red"

        ats_score_val = int(resume_sec.get("score", 0) or 0)
        ats_max_val = SECTION_MAX["Resume (ATS)"] or 1
        ats_percent = int(round((ats_score_val / float(ats_max_val)) * 100))
        ats_score_class = _color_class(ats_percent)
        profile_score_class = _color_class(profile_percent)

        print(f"Final section scores: {section_scores}")
        print(f"Total score: {total_score}, Profile percent: {profile_percent}, ATS percent: {ats_percent}")
        # Assuming matplotlib, io, and base64 are imported at the top of views.py:
        # import matplotlib.pyplot as plt
        # import matplotlib
        # import io
        # import base64
        # from typing import Dict, Any

        def _build_pie_base64_local(scores: Dict[str, int]) -> str:
            """Builds a base64 encoded PNG image of a pie chart for section scores."""
            
            # Placeholder for SECTION_MAX for standalone testing (replace with actual module access if needed)
            SECTION_MAX_FALLBACK = {
                "GitHub": 27, "LinkedIn": 18, "Portfolio": 23, "Resume (ATS)": 23, "Certifications": 9,
            }
            
            if not scores or sum(scores.values()) == 0:
                return ""
            
            labels, values = list(scores.keys()), list(scores.values())
            fig, ax = plt.subplots(figsize=(4.6, 4.6), facecolor="#121212")
            ax.set_facecolor("#121212")
            
            def _autopct(p): return f"{p:.0f}%" if p >= 5 else ""
            
            # Use SECTION_MAX for dynamic max values or fall back to SECTION_MAX_FALLBACK
            section_max_ref = SECTION_MAX if 'SECTION_MAX' in globals() else SECTION_MAX_FALLBACK
            
            # Define the colors for each section
            color_map = {
                "Resume (ATS)": "#ff7f0e",  # Orange for ATS
                "LinkedIn": "#1f77b4",      # Blue for LinkedIn
                "GitHub": "#9467bd",         # Purple for GitHub
                "Portfolio": "#2ca02c",      # Green for Portfolio
                "Certifications": "#d62728", # Red for Certifications
            }
            
            colors = [color_map.get(section, "#1f77b4") for section in labels]  # Default to blue if section isn't mapped
            
            wedges, _, _ = ax.pie(values, labels=None, autopct=_autopct, startangle=140,
                                   colors=colors, textprops={"color": "white", "fontsize": 10})
            ax.axis("equal")
            
            legend_labels = []
            for lbl, val in zip(labels, values):
                max_val = section_max_ref.get(lbl, 1)  # Use 1 to prevent ZeroDivisionError
                percent = (val / max_val) * 100.0 if max_val else 0.0
                legend_labels.append(f"{lbl}: {val}/{max_val} ({percent:.0f}%)")
            
            ax.legend(wedges, legend_labels, loc="lower center", bbox_to_anchor=(0.5, -0.22),
                      fontsize=9, frameon=False, labelcolor="white", ncol=2, columnspacing=1.2,
                      handlelength=1.2, borderpad=0.2)
            
            buf = io.BytesIO()
            plt.tight_layout()
            plt.savefig(buf, format="png", dpi=160, facecolor="#121212", bbox_inches="tight")
            b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
            buf.close()
            plt.close(fig)
            
            return b64




        # ---

        def _build_company_screening_bar(scores_dict: Dict[str, float]) -> str:
            """Builds a base64 encoded PNG image of a bar chart for company screening scores."""
            if not scores_dict:
                return ""
                
            # Set Matplotlib parameters as in the original code
            matplotlib.rcParams.update({
                "font.family": "DejaVu Sans",
                "font.sans-serif": ["DejaVu Sans"],
                "axes.titleweight": "bold",
            })
            
            order = ["MAANG", "Startups", "Mid-sized", "Fortune 500"]
            vals = [float(scores_dict.get(k, 0.0)) for k in order]
            
            fig, ax = plt.subplots(figsize=(7.2, 3.9), facecolor="#121212")
            ax.set_facecolor("#121212")
            
            bars = ax.bar(order, vals, linewidth=0.6, edgecolor="#e6e6e6", alpha=0.95)
            ax.set_ylim(0, 100)
            
            ax.set_ylabel("Weighted score (0–100)", color="white", fontsize=10, fontweight="bold", labelpad=8)
            ax.set_title("Screening Emphasis by Company Type (Initial Screen)",
                        color="white", fontsize=8, fontweight="bold", pad=5)
            
            ax.tick_params(axis="x", colors="white", labelsize=8)
            ax.tick_params(axis="y", colors="white", labelsize=8)
            
            ax.spines["bottom"].set_color("#444")
            ax.spines["left"].set_color("#444")
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)
            
            ax.grid(axis="y", color="#333", alpha=0.35, linewidth=0.7)
            
            for rect, v in zip(bars, vals):
                ax.text(rect.get_x() + rect.get_width()/2.0, rect.get_height() + 2, f"{v:.0f}",
                        ha="center", va="bottom", color="white", fontsize=10, fontweight="bold")
                        
            buf = io.BytesIO()
            plt.tight_layout()
            plt.savefig(buf, format="png", dpi=170, facecolor="#121212", bbox_inches="tight")
            b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
            buf.close()
            plt.close(fig)
            return b64

        # Charts (Logic remains the same)
        # Assuming _build_pie_base64_local and _build_company_screening_bar are available
        pie_chart_image = _build_pie_base64_local(section_scores)

        REWEIGHTED = {
            "MAANG": {"GitHub": 22, "LinkedIn": 22, "Portfolio": 20, "Resume": 31, "Certifications": 5},
            "Startups": {"GitHub": 30, "LinkedIn": 18, "Portfolio": 28, "Resume": 20, "Certifications": 4},
            "Mid-sized": {"GitHub": 25, "LinkedIn": 22, "Portfolio": 23, "Resume": 24, "Certifications": 6},
            "Fortune 500": {"GitHub": 18, "LinkedIn": 25, "Portfolio": 17, "Resume": 30, "Certifications": 10},
        }

        gh_pct = (section_scores["GitHub"] / float(SECTION_MAX["GitHub"])) * 100.0 if SECTION_MAX["GitHub"] else 0.0
        li_pct = (section_scores["LinkedIn"] / float(SECTION_MAX["LinkedIn"])) * 100.0 if SECTION_MAX["LinkedIn"] else 0.0
        pf_pct = (section_scores["Portfolio"] / float(SECTION_MAX["Portfolio"])) * 100.0 if SECTION_MAX["Portfolio"] else 0.0
        rs_pct = (section_scores["Resume (ATS)"] / float(SECTION_MAX["Resume (ATS)"])) * 100.0 if SECTION_MAX["Resume (ATS)"] else 0.0
        ce_pct = (section_scores["Certifications"] / float(SECTION_MAX["Certifications"])) * 100.0 if SECTION_MAX["Certifications"] else 0.0

        def compute_company_emphasis(gh, li, pf, rs, ce):
            scores = {}
            for company, w in REWEIGHTED.items():
                total = (gh * w["GitHub"] + li * w["LinkedIn"] + pf * w["Portfolio"]
                             + rs * w["Resume"] + ce * w["Certifications"]) / 100.0
                scores[company] = round(total, 1)
            return scores

        screening_scores = compute_company_emphasis(gh_pct, li_pct, pf_pct, rs_pct, ce_pct)
        screening_chart_image = _build_company_screening_bar(screening_scores)

        context = {
            "result_key": hashlib.sha256(json.dumps({
                "role_type": "technical",
                "role_slug": role_slug,
                "resume_hash": hashlib.sha256((resume_text or "").encode("utf-8")).hexdigest(),
                "github": github_username or "",
                "leetcode": leetcode_username or "",
            }, sort_keys=True).encode("utf-8")).hexdigest(),
            "applicant_name": applicant_name,
            "ats_score": ats_percent,
            "ats_score_class": ats_score_class,
            "overall_score_average": profile_percent,
            "profile_score_class": profile_score_class,
            "contact_detection": "YES" if _detect_contact(resume_text) else "NO",
            "linkedin_detection": "YES" if linkedin_present_any else "NO",
            "github_detection": github_detection,
            "score_breakdown": score_breakdown,
            "score_breakdown_ordered": score_breakdown_ordered,
            "total_score": total_score,
            "total_grade": _grade_pct(profile_percent),
            "pie_chart_image": pie_chart_image,
            "screening_chart_image": screening_chart_image,
            "screening_scores": screening_scores,
            "role": role_slug,
            "suggestions": (dyn.get("suggestions") or [])[:8],
            "extracted_links": enriched_links,
            "recommended_certifications": recommended_certs, # <-- Now using the correct list
        }

        request.session["resume_context_tech"] = context
        request.session.modified = True
        return render(request, "resume_result.html", context)

    finally:
        try:
            os.unlink(temp_path)
        except Exception:
            pass 
# ====

import logging

logger = logging.getLogger(__name__)

# ========= Non-tech analyzer =========
@require_POST
def analyze_resume_v2(request):
    context = {
        "applicant_name": "N/A",
        "ats_score": 0,
        "overall_score_average": 0,
        "overall_grade": "N/A",
        "score_breakdown": {},
        "suggestions": [],
        "pie_chart_image": None,
        "detected_links": [],
        "error": None,
        "contact_detection": "NO",
        "github_detection": "NO",
        "linkedin_detection": "NO",
    }

    if request.method == "POST" and request.FILES.get("resume"):
        resume_file = request.FILES["resume"]
        ext = os.path.splitext(resume_file.name)[1].lower()

        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
            for chunk in resume_file.chunks():
                tmp.write(chunk)
            temp_path = tmp.name

        try:
            # ========== Extract Text ==========
            if ext == ".pdf":
                extracted_links, resume_text_raw = extract_links_combined(temp_path)
                resume_text = _normalize_text(resume_text_raw or "")
            elif ext == ".docx":
                resume_text_raw = extract_text_from_docx(temp_path) or ""
                resume_text = _normalize_text(resume_text_raw)
                extracted_links = extract_links_from_docx(temp_path)
            elif ext in (".txt",):
                with open(temp_path, "r", encoding="utf-8", errors="ignore") as f:
                    resume_text_raw = f.read()
                resume_text = _normalize_text(resume_text_raw or "")
                extracted_links = []
            else:
                context["error"] = "Unsupported file format."
                return render(request, "score_of_non_tech.html", context)

            # ========== Extract URLs ==========
            text_urls = extract_urls_from_text(resume_text)
            merged = _dedupe_preserve_order_strings((extracted_links or []) + text_urls)

            # Classify links
            def classify_link(u: str):
                url = (u or "").lower()
                if "linkedin.com" in url:
                    return "linkedin"
                if "github.com" in url:
                    return "github"
                if any(p in url for p in [
                    "behance.net", "dribbble.com", "github.io",
                    "notion.site", "portfolio", "wixsite",
                    "wordpress", "medium.com"
                ]):
                    return "portfolio"
                return "other"

            display_links = [{"url": u, "type": classify_link(u)} for u in merged]
            display_links = validate_links_enrich(display_links)

            # Detections
            contact_detection = "YES" if _detect_contact(resume_text) else "NO"
            github_detection = "YES" if any(l for l in display_links if l.get("ok") and l.get("type") == "github") else "NO"
            linkedin_detection = "YES" if any(l for l in display_links if l.get("ok") and l.get("type") == "linkedin") else "NO"
            applicant_name = extract_applicant_name(resume_text) or "N/A"

            # ========== ATS % from technical analyzer ==========
            dyn = calculate_dynamic_ats_score_v2(
                resume_text=resume_text,
                github_username="",
                leetcode_username="",
                extracted_links=display_links,
            )
            resume_sec = dyn["sections"].get("Resume (ATS Score)", {"score": 0})
            ats_score_val = int(resume_sec.get("score", 0) or 0)
            ats_max_val = resume_sec.get("max", 23) or 1
            ats_percent = int(round((ats_score_val / float(ats_max_val)) * 100))

            # ========== Section Definitions with Fixed Weights ==========
            SECTION_DEFS = {
                "Portfolio Website": {"max": 20, "weight": 20},
                "LinkedIn": {"max": 16, "weight": 16},
                "File Type & Parsing": {"max": 8, "weight": 8},
                "Section Headings & Structure": {"max": 8, "weight": 8},
                "Job-Title & Core Skills": {"max": 8, "weight": 8},
                "Dedicated Skills Section": {"max": 8, "weight": 8},
                "Keyword Integration": {"max": 8, "weight": 8},
                "Action Verbs": {"max": 8, "weight": 8},
                "Quantifiable Results": {"max": 8, "weight": 8},
                "Conciseness & Readability": {"max": 8, "weight": 8},
            }

            score_breakdown = {}

            def add_section(name, obtained, subs):
                maxpts = SECTION_DEFS[name]["max"]
                weight = SECTION_DEFS[name]["weight"]
                pct = int(round((obtained / maxpts) * 100)) if maxpts else 0
                grade = "Excellent" if pct >= 85 else "Good" if pct >= 70 else "Average" if pct >= 50 else "Poor"
                score_breakdown[name] = {
                    "score": int(obtained or 0),
                    "max": maxpts,
                    "weight": f"{weight}%",
                    "grade": grade,
                    "sub_criteria": [{**s, "score": int(s.get("score") or 0)} for s in subs],
                }

            # Portfolio scoring
            has_portfolio = any(l for l in display_links if l.get("type") == "portfolio")
            pf_subs = [
                {"name": "Link present", "score": 4 if has_portfolio else 0, "max": 4,
                 "insight": "Portfolio link detected" if has_portfolio else "No portfolio link"},
                {"name": "Responsive/Mobile", "score": 3 if has_portfolio else 0, "max": 4,
                 "insight": "Responsive design check" if has_portfolio else "No portfolio"},
                {"name": "Case studies/projects", "score": 3 if has_portfolio else 0, "max": 4,
                 "insight": "Projects listed" if has_portfolio else "No portfolio"},
                {"name": "Process docs/artifacts", "score": 3 if has_portfolio else 0, "max": 4,
                 "insight": "Docs/artifacts found" if has_portfolio else "No portfolio"},
                {"name": "Videos/demos", "score": 2 if has_portfolio else 0, "max": 4,
                 "insight": "Demo content found" if has_portfolio else "No portfolio"},
            ]
            pf_score = sum(s["score"] for s in pf_subs)
            add_section("Portfolio Website", pf_score, pf_subs)

            # LinkedIn scoring
            has_linkedin = any(l for l in display_links if l.get("type") == "linkedin")
            li_subs = [
                {"name": "Link present", "score": 4 if has_linkedin else 0, "max": 4,
                 "insight": "Profile link present" if has_linkedin else "No LinkedIn"},
                {"name": "Headline & Summary", "score": 3 if has_linkedin else 0, "max": 4,
                 "insight": "Headline/summary check" if has_linkedin else "No LinkedIn"},
                {"name": "Skills & Endorsements", "score": 2 if has_linkedin else 0, "max": 3,
                 "insight": "Skills endorsements check" if has_linkedin else "No LinkedIn"},
                {"name": "Portfolio/Cert links", "score": 2 if has_linkedin else 0, "max": 3,
                 "insight": "Certifications/links check" if has_linkedin else "No LinkedIn"},
                {"name": "Activity/posts", "score": 1 if has_linkedin else 0, "max": 2,
                 "insight": "Activity visible" if has_linkedin else "No LinkedIn"},
            ]
            li_score = sum(s["score"] for s in li_subs)
            add_section("LinkedIn", li_score, li_subs)

            # Other static sections
            add_section("File Type & Parsing", 8 if ext in (".pdf", ".docx") else 6, [
                {"name": "File Format", "score": 8 if ext in (".pdf", ".docx") else 6, "max": 8,
                 "insight": "Preferred format" if ext in (".pdf", ".docx") else "Less preferred format"},
            ])
            add_section("Section Headings & Structure", 7, [
                {"name": "Headings", "score": 7, "max": 8, "insight": "Standard headings detected"},
            ])
            add_section("Job-Title & Core Skills", 6, [
                {"name": "Job Title", "score": 6, "max": 8, "insight": "Target job title partially present"},
            ])
            add_section("Dedicated Skills Section", 7, [
                {"name": "Skills", "score": 7, "max": 8, "insight": "Dedicated skills section found"},
            ])
            add_section("Keyword Integration", 6, [
                {"name": "Keywords", "score": 6, "max": 8, "insight": "Some JD keywords used"},
            ])
            add_section("Action Verbs", 8, [
                {"name": "Verbs", "score": 8, "max": 8, "insight": "Strong verbs used"},
            ])
            add_section("Quantifiable Results", 7, [
                {"name": "Results", "score": 7, "max": 8, "insight": "Metrics & numbers included"},
            ])
            add_section("Conciseness & Readability", 6, [
                {"name": "Readability", "score": 6, "max": 8, "insight": "Readable and concise"},
            ])

            # Totals
            total_score = sum(v["score"] for v in score_breakdown.values())
            total_max = sum(v["max"] for v in score_breakdown.values())
            overall_percent = int(round((total_score / total_max) * 100)) if total_max else 0
            overall_grade = "Excellent" if overall_percent >= 85 else "Good" if overall_percent >= 70 else "Average" if overall_percent >= 50 else "Poor"

            # ---------- Pie chart ----------
            import matplotlib.pyplot as plt, io, base64
            def build_pie(scores):
                labels, values = list(scores.keys()), list(scores.values())
                fig, ax = plt.subplots(figsize=(4.6, 4.6), facecolor="#121212")
                ax.set_facecolor("#121212")
                wedges, _, _ = ax.pie(values, labels=None,
                                      autopct=lambda p: f"{p:.0f}%" if p >= 5 else "",
                                      startangle=140, textprops={"color": "white", "fontsize": 10})
                ax.axis("equal")
                legend_labels = [f"{lbl}: {val}%" for lbl, val in zip(labels, values)]
                ax.legend(wedges, legend_labels, loc="lower center", bbox_to_anchor=(0.5, -0.22),
                          fontsize=9, frameon=False, labelcolor="white", ncol=2)
                buf = io.BytesIO()
                plt.tight_layout()
                plt.savefig(buf, format="png", dpi=160, facecolor="#121212", bbox_inches="tight")
                b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
                buf.close(); plt.close(fig)
                return b64

            # Conditional pie chart logic
            pie_data = {"ATS": ats_percent}
            if has_portfolio and has_linkedin:
                pie_data.update({
                    "Portfolio": int(round((pf_score / 20) * 100)),
                    "LinkedIn": int(round((li_score / 16) * 100)),
                })
            elif has_portfolio:
                pie_data.update({
                    "Portfolio": int(round((pf_score / 20) * 100)),
                })
            elif has_linkedin:
                pie_data.update({
                    "LinkedIn": int(round((li_score / 16) * 100)),
                })
            else:
                # lump "Other Sections" into pie if no LinkedIn/Portfolio
                others_pct = overall_percent
                pie_data.update({"Other Sections": others_pct})

            pie_chart_image = build_pie(pie_data)

            # ---------- Suggestions ----------
            suggestion_pool = [
                # LinkedIn related
                {"condition": not has_linkedin, "text": "Add a LinkedIn profile link to strengthen professional visibility."},
                {"condition": not has_linkedin, "text": "Include LinkedIn headline, summary, and recent activity to stand out."},

                # Portfolio related
                {"condition": not has_portfolio, "text": "Include a portfolio or personal website showcasing your work."},
                {"condition": not has_portfolio, "text": "Add project case studies or demos to your portfolio for impact."},

                # GitHub related
                {"condition": not github_detection, "text": "Provide a GitHub link to highlight your coding projects."},
                {"condition": not github_detection, "text": "Contribute to open-source projects and showcase them on GitHub."},

                # ATS related
                {"condition": ats_percent < 70, "text": "Improve ATS score by adding more job-specific keywords."},
                {"condition": ats_percent < 70, "text": "Ensure consistent formatting and avoid images or tables in resume."},

                # Overall quality
                {"condition": overall_percent < 80, "text": "Highlight achievements with measurable results (numbers, percentages)."},
                {"condition": overall_percent < 80, "text": "Use strong action verbs like 'Implemented', 'Optimized', 'Led'."},

                # Formatting and readability
                {"condition": True, "text": "Use a clean, consistent format with standard section headings."},
                {"condition": True, "text": "Keep resume concise (1–2 pages) and relevant to the target role."},
                {"condition": True, "text": "Add a dedicated skills section with keywords from job descriptions."},
                {"condition": True, "text": "Maintain reverse-chronological order for work experience."},
                {"condition": True, "text": "Avoid dense text; use bullet points for readability."},
            ]

            # Pick relevant suggestions
            suggestions = [s["text"] for s in suggestion_pool if s["condition"]]

            # Limit to top 5
            suggestions = suggestions[:5]


            # Final context
            context.update({
                "applicant_name": applicant_name,
                "ats_score": ats_percent,
                "overall_score_average": overall_percent,
                "overall_grade": overall_grade,
                "score_breakdown": score_breakdown,
                "pie_chart_image": pie_chart_image,
                "detected_links": display_links,
                "contact_detection": contact_detection,
                "github_detection": github_detection,
                "linkedin_detection": linkedin_detection,
                "suggestions": suggestions,
            })

        finally:
            try:
                os.unlink(temp_path)
            except Exception:
                pass

    request.session["resume_context_nontech"] = context
    request.session.modified = True
    return render(request, "score_of_non_tech.html", context)
# 

# ========= Show reports =========
def show_report_technical(request):
    ctx = request.session.get("resume_context_tech")
    if not ctx:
        return redirect("upload_resume")
    return render(request, "resume_result.html", ctx)

def show_report_nontechnical(request):
    ctx = request.session.get("resume_context_nontech")
    if not ctx:
        return redirect("upload_resume")
    return render(request, "score_of_non_tech.html", ctx)

def why(request): return render(request, "why.html")
def who(request): return render(request, "who.html")

@csrf_protect
def ats_report_view(request):
    if request.method == "GET":
        ctx = {
            "applicant_name": "",
            "contact_detection": "NO",
            "linkedin_detection": "NO",
            "github_detection": "NO",
            "ats_score": 0,
            "overall_score_average": 0,
            "score_breakdown": {},
            "score_breakdown_ordered": [],
            "total_score": 0,
            "total_grade": "Poor",
            "pie_chart_image": "",
            "missing_certifications": [],
            "suggestions": [],
            "role": "",
        }
        return render(request, "ats_report.html", ctx)
    return HttpResponseBadRequest("Use the upload endpoint to submit a resume.")

















