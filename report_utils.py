"""Shareable HTML/PDF reports for scans and security audits."""

from __future__ import annotations

import html
import json
import os
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _risk_class(value: Any) -> str:
    return {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "safe": "safe",
    }.get(str(value).lower(), "neutral")


def build_report_html(
    devices: Iterable[Dict[str, Any]],
    *,
    scan_result: Optional[Dict[str, Any]] = None,
    security_result: Optional[Dict[str, Any]] = None,
    title: str = "Wi-Fi Device Scanner Report",
) -> str:
    """Build a self-contained report that can be opened or shared offline."""
    device_list = [d for d in devices if isinstance(d, dict)]
    scan_result = scan_result or {}
    security_result = security_result or {}
    events = scan_result.get("events") or []
    findings = security_result.get("findings") or []
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = []
    for index, device in enumerate(device_list, 1):
        confidence = device.get("confidence")
        confidence_text = f"{float(confidence) * 100:.0f}%" if isinstance(confidence, (int, float)) else "-"
        rows.append(
            "<tr>"
            f"<td>{index}</td><td>{_esc(device.get('alias') or device.get('name') or '—')}</td>"
            f"<td><code>{_esc(device.get('ip'))}</code></td><td><code>{_esc(device.get('ipv6') or '—')}</code></td><td><code>{_esc(device.get('mac'))}</code></td>"
            f"<td>{_esc(device.get('vendor') or 'Chưa rõ')}</td><td>{_esc(device.get('category') or 'unknown')}</td>"
            f"<td>{_esc(device.get('room') or '—')}</td><td>{confidence_text} ({_esc(device.get('confidence_label') or '—')})</td>"
            f"<td>{'Tin cậy' if device.get('trusted') else 'Chưa đánh dấu'}</td></tr>"
        )
    event_rows = []
    for event in events:
        event_type = event.get("event_type", "")
        device = event.get("device") or event.get("details", {}).get("device") or {}
        event_rows.append(
            f"<tr><td><span class=\"badge {_risk_class('medium' if event_type != 'new' else 'safe')}\">{_esc(event_type)}</span></td>"
            f"<td>{_esc(device.get('alias') or device.get('name') or device.get('ip') or '—')}</td>"
            f"<td>{_esc(device.get('ip'))}</td><td>{_esc(device.get('mac'))}</td></tr>"
        )
    finding_rows = []
    for finding in findings:
        risk = finding.get("risk", "safe")
        finding_rows.append(
            f"<tr><td><span class=\"badge {_risk_class(risk)}\">{_esc(risk)}</span></td>"
            f"<td>{_esc(finding.get('check'))}</td><td>{_esc(finding.get('host'))}:{_esc(finding.get('port', ''))}</td>"
            f"<td>{_esc(finding.get('status'))}</td><td>{_esc(finding.get('evidence'))}</td>"
            f"<td>{_esc(finding.get('remediation'))}</td></tr>"
        )
    dns = security_result.get("dns") or {}
    visibility = scan_result.get("visibility") or {}
    return f"""<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(title)}</title>
<style>
:root {{ color-scheme: light; --ink:#172033; --muted:#637083; --line:#d9e0ea; --panel:#f7f9fc; --accent:#0f766e; }}
* {{ box-sizing:border-box; }} body {{ margin:0; font-family:Segoe UI,Arial,sans-serif; color:var(--ink); background:#eef3f8; }}
main {{ max-width:1180px; margin:0 auto; padding:32px 22px 56px; }} header {{ background:linear-gradient(120deg,#0f766e,#155e75); color:#fff; padding:28px 30px; border-radius:18px; box-shadow:0 12px 30px #0f172a22; }}
h1 {{ margin:0 0 6px; font-size:29px; }} h2 {{ margin:26px 0 10px; font-size:19px; }} .sub {{ opacity:.86; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; margin-top:18px; }} .metric {{ background:#fff; border:1px solid var(--line); border-radius:12px; padding:14px 16px; }} .metric b {{ display:block; font-size:23px; color:var(--accent); }}
.panel {{ background:#fff; border:1px solid var(--line); border-radius:14px; padding:4px 14px 14px; overflow:auto; }} table {{ width:100%; border-collapse:collapse; font-size:13px; }} th,td {{ text-align:left; vertical-align:top; padding:10px 8px; border-bottom:1px solid #edf0f4; }} th {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.04em; }} code {{ font-family:Consolas,monospace; }}
.badge {{ display:inline-block; border-radius:999px; padding:3px 8px; font-size:11px; font-weight:700; }} .critical {{ background:#fee2e2; color:#991b1b; }} .high {{ background:#ffedd5; color:#9a3412; }} .medium {{ background:#fef3c7; color:#92400e; }} .low {{ background:#e0f2fe; color:#075985; }} .safe {{ background:#dcfce7; color:#166534; }} .neutral {{ background:#e5e7eb; color:#374151; }}
.notice {{ background:#ecfeff; border-left:4px solid #0891b2; padding:12px 14px; border-radius:8px; color:#164e63; }} footer {{ color:var(--muted); font-size:12px; margin-top:24px; }}
@media print {{ body {{ background:#fff; }} main {{ max-width:none; padding:0; }} header {{ box-shadow:none; }} .panel {{ break-inside:avoid; }} }}
</style></head><body><main>
<header><h1>{_esc(title)}</h1><div class=sub>Generated {generated} • Kết quả quan sát trong mạng LAN hiện tại</div></header>
<section class=grid>
<div class=metric><span>Thiết bị</span><b>{len(device_list)}</b></div>
<div class=metric><span>Sự kiện thay đổi</span><b>{len(events)}</b></div>
<div class=metric><span>Cảnh báo dịch vụ</span><b>{len([x for x in findings if x.get('risk') not in ('safe','low')])}</b></div>
<div class=metric><span>Độ phủ quan sát</span><b>{_esc(visibility.get('status') or '—')}</b></div>
</section>
<h2>Thiết bị trong snapshot</h2><div class=panel><table><thead><tr><th>#</th><th>Tên</th><th>IPv4</th><th>IPv6</th><th>MAC</th><th>Hãng</th><th>Loại</th><th>Phòng</th><th>Độ tin cậy</th><th>Tin cậy</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan=10>Không có dữ liệu</td></tr>'}</tbody></table></div>
<h2>Lịch sử và cảnh báo</h2><div class=panel><table><thead><tr><th>Loại</th><th>Thiết bị</th><th>IP</th><th>MAC</th></tr></thead><tbody>{''.join(event_rows) or '<tr><td colspan=4>Không có thay đổi trong lần này</td></tr>'}</tbody></table></div>
<h2>Security dashboard</h2><div class=notice>DNS chính: <b>{_esc(dns.get('primary_dns') or '—')}</b> • Canary: <b>{'OK' if dns.get('canary_test_ok') else 'Không xác minh được'}</b>. Cổng mở hoặc banner là bằng chứng quan sát, không phải kết luận tuyệt đối.</div>
<div class=panel style="margin-top:10px"><table><thead><tr><th>Rủi ro</th><th>Kiểm tra</th><th>Host/port</th><th>Trạng thái</th><th>Bằng chứng</th><th>Khắc phục</th></tr></thead><tbody>{''.join(finding_rows) or '<tr><td colspan=6>Chưa có finding</td></tr>'}</tbody></table></div>
<footer>Wifi Device Scanner • Báo cáo chỉ dùng cho mạng bạn sở hữu hoặc được phép kiểm tra.</footer>
</main></body></html>"""


def export_report_html(
    devices: Iterable[Dict[str, Any]], filepath: str, *, scan_result: Optional[Dict[str, Any]] = None, security_result: Optional[Dict[str, Any]] = None
) -> bool:
    try:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(build_report_html(devices, scan_result=scan_result, security_result=security_result), encoding="utf-8")
        return True
    except OSError:
        return False


def export_report_pdf(
    devices: Iterable[Dict[str, Any]], filepath: str, *, scan_result: Optional[Dict[str, Any]] = None, security_result: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Render a PDF with reportlab when available; return actionable status."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    except Exception as exc:
        return {"ok": False, "error": "reportlab chưa được cài đặt", "detail": str(exc)}
    try:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        device_list = [d for d in devices if isinstance(d, dict)]
        scan_result = scan_result or {}
        security_result = security_result or {}
        # Helvetica cannot encode Vietnamese. Prefer an installed Windows
        # Unicode font and fall back gracefully on portable/non-Windows runs.
        font_name = "Helvetica"
        for candidate in (
            os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Fonts", "segoeui.ttf"),
            os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Fonts", "arial.ttf"),
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        ):
            if os.path.exists(candidate):
                try:
                    pdfmetrics.registerFont(TTFont("WDSUnicode", candidate))
                    font_name = "WDSUnicode"
                    break
                except Exception:
                    continue
        styles = getSampleStyleSheet()
        for style in styles.byName.values():
            style.fontName = font_name
        styles.add(ParagraphStyle(name="SmallMuted", parent=styles["Normal"], fontName=font_name, fontSize=8, textColor=colors.HexColor("#637083"), leading=10))
        styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], fontName=font_name, textColor=colors.HexColor("#0f766e"), spaceBefore=12, spaceAfter=6))
        story = [Paragraph("Wi-Fi Device Scanner Report", styles["Title"]), Paragraph(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), styles["SmallMuted"]), Spacer(1, 8)]
        story.append(Paragraph(f"Thiết bị: {len(device_list)} • Sự kiện: {len(scan_result.get('events') or [])}", styles["Normal"]))
        story.append(Spacer(1, 8))
        story.append(Paragraph("Thiết bị", styles["Section"]))
        cell_style = ParagraphStyle(name="Cell", parent=styles["Normal"], fontName=font_name, fontSize=7, leading=8)
        head_style = ParagraphStyle(name="HeadCell", parent=cell_style, textColor=colors.white, fontName=font_name)
        data = [[Paragraph(_esc(x), head_style) for x in ["Tên", "IPv4", "IPv6", "MAC", "Hãng", "Loại", "Phòng", "Độ tin cậy", "Tin cậy"]]]
        for d in device_list:
            confidence = d.get("confidence")
            confidence_text = f"{float(confidence) * 100:.0f}%" if isinstance(confidence, (int, float)) else "-"
            data.append([Paragraph(_esc(value), cell_style) for value in [str(d.get("alias") or d.get("name") or "-"), str(d.get("ip") or ""), str(d.get("ipv6") or "-"), str(d.get("mac") or ""), str(d.get("vendor") or "Chưa rõ"), str(d.get("category") or "unknown"), str(d.get("room") or "-"), confidence_text, "Có" if d.get("trusted") else "Chưa"]])
        table = Table(data, repeatRows=1, colWidths=[30 * mm, 23 * mm, 37 * mm, 33 * mm, 31 * mm, 21 * mm, 21 * mm, 22 * mm, 18 * mm])
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f766e")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTNAME", (0, 0), (-1, -1), font_name), ("GRID", (0, 0), (-1, -1), .25, colors.HexColor("#d9e0ea")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story += [table, Spacer(1, 8)]
        visibility = scan_result.get("visibility") or {}
        story.append(Paragraph(
            f"Quan sát: {visibility.get('status', '—')} • {visibility.get('found_hosts', len(device_list))} host • "
            f"Bằng chứng: {'; '.join(visibility.get('evidence') or []) or 'Không có cảnh báo'}",
            styles["SmallMuted"],
        ))
        events = scan_result.get("events") or []
        if events:
            story.append(Paragraph("Lịch sử và cảnh báo", styles["Section"]))
            event_lines = []
            for event in events[:40]:
                device = event.get("device") or event.get("details", {}).get("device") or {}
                event_lines.append(f"{event.get('event_type', '')}: {device.get('alias') or device.get('name') or device.get('ip') or '—'}")
            story.append(Paragraph("<br/>".join(_esc(line) for line in event_lines), cell_style))
        story += [Spacer(1, 10), Paragraph("Security dashboard", styles["Section"])]
        security_rows = [[Paragraph(_esc(x), head_style) for x in ["Risk", "Check", "Host", "Evidence", "Remediation"]]]
        for f in security_result.get("findings") or []:
            security_rows.append([Paragraph(_esc(value), cell_style) for value in [str(f.get("risk", "safe")), str(f.get("check", "")), f"{f.get('host', '')}:{f.get('port', '')}", str(f.get("evidence", ""))[:100], str(f.get("remediation", ""))[:120]]])
        if len(security_rows) == 1:
            security_rows.append([Paragraph(_esc(x), cell_style) for x in ["-", "-", "-", "Chưa có finding", "-"]])
        sec_table = Table(security_rows, repeatRows=1, colWidths=[18 * mm, 27 * mm, 27 * mm, 58 * mm, 58 * mm])
        sec_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#155e75")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTNAME", (0, 0), (-1, -1), font_name), ("GRID", (0, 0), (-1, -1), .25, colors.HexColor("#d9e0ea")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(sec_table)
        SimpleDocTemplate(str(path), pagesize=landscape(A4), rightMargin=12 * mm, leftMargin=12 * mm, topMargin=12 * mm, bottomMargin=12 * mm).build(story)
        return {"ok": True, "path": str(path)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def export_report_bundle(devices: Iterable[Dict[str, Any]], base_path: str, *, scan_result: Optional[Dict[str, Any]] = None, security_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Write HTML and, when possible, PDF beside it."""
    base = Path(base_path)
    html_path = str(base.with_suffix(".html"))
    pdf_path = str(base.with_suffix(".pdf"))
    html_ok = export_report_html(devices, html_path, scan_result=scan_result, security_result=security_result)
    pdf_res = export_report_pdf(devices, pdf_path, scan_result=scan_result, security_result=security_result)
    return {"html": html_path if html_ok else "", "html_ok": html_ok, "pdf": pdf_res}


__all__ = ["build_report_html", "export_report_html", "export_report_pdf", "export_report_bundle"]
