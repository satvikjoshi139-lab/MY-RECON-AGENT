"""
exports/report_generator.py
Generates a styled PDF security report using reportlab.
Falls back to plain .txt if reportlab is unavailable.
"""
import os
from datetime import datetime

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer,
        Table, TableStyle, HRFlowable,
    )
    from reportlab.lib.enums import TA_CENTER
    REPORTLAB = True
except ImportError:
    REPORTLAB = False

EXPORT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "exports", "reports"
)
os.makedirs(EXPORT_DIR, exist_ok=True)

# ── Colour palette ────────────────────────────────────────────────────────────
_BG     = colors.HexColor("#0b0f1a")
_CARD   = colors.HexColor("#161b22")
_CARD2  = colors.HexColor("#0d1117")
_BORDER = colors.HexColor("#30363d")
_BLUE   = colors.HexColor("#58a6ff")
_GREEN  = colors.HexColor("#3fb950")
_RED    = colors.HexColor("#f85149")
_YELLOW = colors.HexColor("#e3b341")
_MUTED  = colors.HexColor("#8b949e")
_WHITE  = colors.white
_NAVY   = colors.HexColor("#0d1f38")
_DARK_R = colors.HexColor("#2d0f0f")
_DARK_Y = colors.HexColor("#2a1800")
_DARK_G = colors.HexColor("#0f2a1a")


def _ps(name, **kw) -> ParagraphStyle:
    return ParagraphStyle(name, **kw)


def generate_pdf(packet: dict) -> str:
    """Build and save a PDF. Return the file path."""
    rid   = packet.get("request_id", "unknown")[:8]
    fname = f"sentinelx_report_{rid}.pdf"
    fpath = os.path.join(EXPORT_DIR, fname)

    if not REPORTLAB:
        txt = fpath.replace(".pdf", ".txt")
        with open(txt, "w", encoding="utf-8") as f:
            f.write(_plain_text(packet))
        return txt

    doc = SimpleDocTemplate(
        fpath, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )

    risk      = packet.get("risk_level", "LOW")
    score     = packet.get("trust_score", 100)
    decision  = packet.get("trust_decision", "ALLOW")
    url       = packet.get("url", "N/A")
    scan      = packet.get("website_scan") or {}
    ri        = scan.get("risk_indicators", [])
    atk       = packet.get("attack_simulation", [])
    groq_r    = packet.get("groq_response", "N/A")
    pqc_log   = packet.get("pqc_log", [])
    rid_full  = packet.get("request_id", "N/A")
    ts        = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    risk_c    = {"HIGH": _RED, "MEDIUM": _YELLOW, "LOW": _GREEN}.get(risk, _GREEN)

    # ── styles ────────────────────────────────────────────────────────────────
    title_s = _ps("TI", fontSize=22, textColor=_BLUE,  fontName="Helvetica-Bold",  spaceAfter=2)
    sub_s   = _ps("SU", fontSize=9,  textColor=_MUTED, fontName="Helvetica",        spaceAfter=12)
    head_s  = _ps("HE", fontSize=10, textColor=_WHITE, fontName="Helvetica-Bold",   spaceBefore=14, spaceAfter=5,
                   borderPad=4, backColor=colors.HexColor("#1a2035"), borderRadius=2)
    body_s  = _ps("BO", fontSize=9,  textColor=_WHITE, fontName="Helvetica",        spaceAfter=4,  leading=13)
    foot_s  = _ps("FO", fontSize=7,  textColor=_MUTED, fontName="Helvetica",        alignment=TA_CENTER)
    ri_s    = _ps("RI", fontSize=9,  textColor=_YELLOW,fontName="Helvetica",        leftIndent=8,  spaceAfter=3,
                   backColor=_DARK_Y, borderPad=4)
    ok_s    = _ps("OK", fontSize=9,  textColor=_GREEN, fontName="Helvetica",        leftIndent=8,  spaceAfter=3,
                   backColor=_DARK_G, borderPad=4)
    llm_s   = _ps("LLM",fontSize=9, textColor=_WHITE, fontName="Helvetica",        leading=14, spaceAfter=4,
                   backColor=_CARD2, leftIndent=8, rightIndent=8, borderPad=8)

    def tbl(data, widths, extra_style=None):
        t = Table(data, colWidths=widths)
        base = [
            ("FONTNAME",     (0,0), (-1,-1), "Helvetica"),
            ("FONTSIZE",     (0,0), (-1,-1), 8.5),
            ("GRID",         (0,0), (-1,-1), 0.5, _BORDER),
            ("TOPPADDING",   (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0), (-1,-1), 5),
            ("LEFTPADDING",  (0,0), (-1,-1), 7),
            ("ROWBACKGROUNDS",(0,0),(-1,-1), [_CARD2, _CARD]),
            ("TEXTCOLOR",    (0,0), (-1,-1), _WHITE),
        ]
        if extra_style:
            base.extend(extra_style)
        t.setStyle(TableStyle(base))
        return t

    story = []

    # ── Title block ───────────────────────────────────────────────────────────
    story.append(Paragraph("SentinelX AI", title_s))
    story.append(Paragraph("Post-Quantum Security Evaluation Report", sub_s))
    story.append(HRFlowable(width="100%", thickness=1, color=_BORDER))
    story.append(Spacer(1, 8))

    # ── Summary table ─────────────────────────────────────────────────────────
    meta_data = [
        ["Target URL",  url],
        ["Request ID",  rid_full],
        ["Timestamp",   ts],
        ["Trust Score", f"{score}/100"],
        ["Risk Level",  risk],
        ["Decision",    decision],
        ["Threats",     str(packet.get("threat_count", len(ri)))],
    ]
    mt = tbl(meta_data, [4*cm, 13*cm], [
        ("TEXTCOLOR", (0,0), (0,-1), _MUTED),
        ("TEXTCOLOR", (1,3), (1,4),  risk_c),
        ("FONTNAME",  (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME",  (1,3), (1,4),  "Helvetica-Bold"),
        ("FONTSIZE",  (1,3), (1,3),  11),
    ])
    story.append(mt)
    story.append(Spacer(1, 12))

    # ── Website scan ──────────────────────────────────────────────────────────
    story.append(Paragraph("  WEBSITE SCAN", head_s))
    scan_data = [
        ["Forms",   str(scan.get("forms",0)),  "Scripts", str(scan.get("scripts",0))],
        ["Inputs",  str(scan.get("inputs",0)), "Links",   str(scan.get("links",0))],
        ["IFrames", str(scan.get("iframes",0)),"JS Libs", ", ".join(scan.get("js_libs") or ["None"])],
        ["Missing Headers", ", ".join(scan.get("headers_missing") or ["None"]), "", ""],
    ]
    st2 = tbl(scan_data, [3.5*cm, 4*cm, 3.5*cm, 6*cm], [
        ("TEXTCOLOR", (0,0), (0,-1), _MUTED),
        ("TEXTCOLOR", (2,0), (2,-1), _MUTED),
        ("FONTNAME",  (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME",  (2,0), (2,-1), "Helvetica-Bold"),
        ("SPAN",      (1,3), (3,3)),
    ])
    story.append(st2)
    story.append(Spacer(1, 10))

    # ── Risk indicators ───────────────────────────────────────────────────────
    story.append(Paragraph("  RISK INDICATORS", head_s))
    if ri:
        for item in ri:
            story.append(Paragraph(f"▲  {item}", ri_s))
    else:
        story.append(Paragraph("✓  No risk indicators detected", ok_s))
    story.append(Spacer(1, 10))

    # ── Attack simulation ─────────────────────────────────────────────────────
    story.append(Paragraph("  ATTACK SIMULATION RESULTS", head_s))
    atk_rows = [["Attack Type", "Payload", "Status"]]
    for a in atk:
        pl = a["payload"]
        atk_rows.append([a["type"], pl[:52]+"…" if len(pl)>52 else pl, a["status"]])

    sc = {"BLOCKED": _RED, "SANITIZED": _YELLOW, "ALLOWED": _GREEN}
    extra = [
        ("BACKGROUND",  (0,0), (-1,0),  colors.HexColor("#1f6feb")),
        ("TEXTCOLOR",   (0,0), (-1,0),  _WHITE),
        ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
        ("ALIGN",       (2,0), (2,-1),  "CENTER"),
        ("FONTNAME",    (2,1), (2,-1),  "Helvetica-Bold"),
    ]
    for i, a in enumerate(atk, 1):
        extra.append(("TEXTCOLOR", (2,i),(2,i), sc.get(a["status"], _WHITE)))
    at = tbl(atk_rows, [4*cm, 10.5*cm, 2.5*cm], extra)
    story.append(at)
    story.append(Spacer(1, 10))

    # ── LLM response ─────────────────────────────────────────────────────────
    story.append(Paragraph("  LLM SECURITY ASSESSMENT", head_s))
    story.append(Paragraph(groq_r, llm_s))
    story.append(Spacer(1, 10))

    # ── PQC channel log ───────────────────────────────────────────────────────
    if pqc_log:
        story.append(Paragraph("  PQC ENCRYPTED CHANNEL LOG", head_s))
        pqc_rows = [["From", "To", "Mode", "Bytes", "ms", "OK"]]
        for h in pqc_log:
            pqc_rows.append([
                h["from"], h["to"], h["mode"],
                str(h["bytes"]), str(h["ms"]),
                "✓" if h.get("verified") else "✗",
            ])
        pqc_extra = [
            ("BACKGROUND", (0,0),(-1,0),  _NAVY),
            ("TEXTCOLOR",  (0,0),(-1,0),  _BLUE),
            ("FONTNAME",   (0,0),(-1,0),  "Helvetica-Bold"),
            ("FONTNAME",   (0,1),(-1,-1), "Courier"),
            ("FONTSIZE",   (0,0),(-1,-1), 7.5),
            ("TEXTCOLOR",  (0,1),(-1,-1), _BLUE),
            ("TEXTCOLOR",  (5,1),(5,-1),  _GREEN),
            ("ALIGN",      (5,0),(5,-1),  "CENTER"),
        ]
        pt = tbl(pqc_rows, [2.5*cm, 2.8*cm, 6.2*cm, 1.7*cm, 1.5*cm, 1.3*cm], pqc_extra)
        story.append(pt)

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_BORDER))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"Generated by SentinelX AI — Milestone 6  |  {ts}  |  "
        f"PQC Channel: HKDF + AES-256-GCM",
        foot_s
    ))

    doc.build(story)
    return fpath


def _plain_text(packet: dict) -> str:
    lines = [
        "=" * 60, "SentinelX AI — Security Report", "=" * 60,
        f"URL:         {packet.get('url','N/A')}",
        f"Trust Score: {packet.get('trust_score','N/A')}/100",
        f"Risk Level:  {packet.get('risk_level','N/A')}",
        f"Decision:    {packet.get('trust_decision','N/A')}",
        "", "LLM Assessment:", packet.get("groq_response","N/A"), "=" * 60,
    ]
    return "\n".join(lines)
