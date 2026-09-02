import sqlite3
from datetime import datetime
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

DB_NAME = "soar_audit.db"

def init_db():
    """Initializes the SQLite database for SOAR audit records."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action_type TEXT NOT NULL,
            target_ip TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            analyst_notes TEXT NOT NULL,
            status TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def log_event(action_type, target_ip, risk_level, analyst_notes, status="SUCCESS"):
    """Logs an operational action or threat investigation into SQLite."""
    init_db()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO audit_logs (timestamp, action_type, target_ip, risk_level, analyst_notes, status)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, action_type, target_ip, risk_level, analyst_notes, status))
    conn.commit()
    conn.close()

def generate_pdf_report(filename="incident_report.pdf"):
    """Generates a high-impact, professional Landscape PDF Incident Report."""
    init_db()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT timestamp, action_type, target_ip, risk_level, status FROM audit_logs ORDER BY id DESC LIMIT 15')
    rows = cursor.fetchall()
    conn.close()

    # 1. LANDSCAPE Orientation (792pt width) to prevent column squeezing
    doc = SimpleDocTemplate(
        filename, 
        pagesize=landscape(letter),
        rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36
    )
    styles = getSampleStyleSheet()
    story = []

    # 2. Document Header
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=18, textColor=colors.HexColor("#0f172a"), spaceAfter=4)
    sub_style = ParagraphStyle('SubStyle', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor("#475569"), spaceAfter=15)
    
    story.append(Paragraph("🛡️ MSc SOAR Platform - Security Incident Audit Report", title_style))
    story.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} BST | <b>Scope:</b> Automated Triage & Kernel Firewall Actions", sub_style))

    # 3. Text Styles for Table Cells (Forces Auto-Wrapping)
    hdr_style = ParagraphStyle('Hdr', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=10, textColor=colors.white)
    cell_style = ParagraphStyle('Cell', parent=styles['Normal'], fontName='Helvetica', fontSize=9, textColor=colors.HexColor("#1e293b"))
    hash_style = ParagraphStyle('HashCell', parent=styles['Normal'], fontName='Courier', fontSize=8, textColor=colors.HexColor("#0f172a"))

    # 4. Table Header Row
    table_data = [[
        Paragraph("Timestamp", hdr_style),
        Paragraph("Action Executed", hdr_style),
        Paragraph("Target (IP / Domain / Hash)", hdr_style),
        Paragraph("Threat Risk Level", hdr_style),
        Paragraph("Execution Status", hdr_style)
    ]]

    # 5. Populate Data Rows with Auto-Wrapping Paragraphs
    for row in rows:
        ts, action, target, risk, status = row
        
        # Use monospace for targets (IPs/Domains/Hashes) so they wrap cleanly
        target_p = Paragraph(str(target), hash_style)
        
        table_data.append([
            Paragraph(str(ts), cell_style),
            Paragraph(str(action), cell_style),
            target_p,
            Paragraph(str(risk), cell_style),
            Paragraph(str(status), cell_style)
        ])

    # 6. Column Widths optimized for Landscape Widescreen (Total = 720pt)
    col_widths = [120, 140, 260, 100, 100]
    
    t = Table(table_data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
    ]))
    
    story.append(t)
    doc.build(story)
    return filename

if __name__ == "__main__":
    init_db()
    print("Audit Logger initialized.")
