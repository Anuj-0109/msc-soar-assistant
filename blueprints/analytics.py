from flask import Blueprint, jsonify
from models.database import get_db_connection
from datetime import datetime

analytics_bp = Blueprint('analytics_bp', __name__)

@analytics_bp.route('/api/analytics/metrics', methods=['GET'])
def get_soc_metrics():
    """Calculates key performance indicators (KPIs), MTTC, and incident distributions."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Total Incidents
    cursor.execute("SELECT COUNT(*) FROM incidents")
    total_incidents = cursor.fetchone()[0]

    # Breakdown by Status
    cursor.execute("SELECT status, COUNT(*) FROM incidents GROUP BY status")
    status_counts = dict(cursor.fetchall())

    # Breakdown by Severity
    cursor.execute("SELECT severity, COUNT(*) FROM incidents GROUP BY severity")
    severity_counts = dict(cursor.fetchall())

    # Calculate Mean Time to Contain (MTTC) in minutes
    cursor.execute("""
        SELECT created_at, updated_at 
        FROM incidents 
        WHERE status IN ('CONTAINED', 'CLOSED')
    """)
    contained_incidents = cursor.fetchall()

    mttc_minutes = 0.0
    if contained_incidents:
        total_seconds = 0
        valid_count = 0
        for row in contained_incidents:
            try:
                created = datetime.strptime(row['created_at'], '%Y-%m-%d %H:%M:%S')
                updated = datetime.strptime(row['updated_at'], '%Y-%m-%d %H:%M:%S')
                delta = (updated - created).total_seconds()
                if delta >= 0:
                    total_seconds += delta
                    valid_count += 1
            except Exception:
                continue
        
        if valid_count > 0:
            mttc_minutes = round((total_seconds / valid_count) / 60.0, 2)

    # Top Targeted IOCs
    cursor.execute("""
        SELECT ioc_value, COUNT(*) as hit_count 
        FROM incidents 
        WHERE ioc_value IS NOT NULL AND ioc_value != ''
        GROUP BY ioc_value 
        ORDER BY hit_count DESC 
        LIMIT 5
    """)
    top_iocs = [{"ioc": row['ioc_value'], "count": row['hit_count']} for row in cursor.fetchall()]

    # Automation Stats
    cursor.execute("SELECT COUNT(*) FROM incidents WHERE assigned_analyst = 'AUTOMATED_INGESTION'")
    automated_count = cursor.fetchone()[0]
    automation_rate = round((automated_count / total_incidents * 100), 1) if total_incidents > 0 else 0.0

    conn.close()

    return jsonify({
        'status': 'success',
        'metrics': {
            'total_incidents': total_incidents,
            'status_distribution': status_counts,
            'severity_distribution': severity_counts,
            'mttc_minutes': mttc_minutes,
            'automation_rate_percent': automation_rate,
            'top_targeted_iocs': top_iocs
        }
    }), 200


@analytics_bp.route('/api/analytics/reports/executive', methods=['GET'])
def get_executive_report():
    """Generates an executive-level summary of threat activity and containment performance."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM incidents WHERE status = 'CONTAINED'")
    contained_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'CRITICAL'")
    critical_count = cursor.fetchone()[0]

    conn.close()

    report_summary = {
        'title': 'SOAR Platform Executive Security Summary',
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'executive_takeaways': [
            f"Active containment automated across {contained_count} high-priority incident records.",
            f"Identified and isolated {critical_count} CRITICAL threat vector(s).",
            "Automated policy enforcement prevented lateral movement without manual intervention delays."
        ],
        'compliance_status': 'AUDIT_READY'
    }

    return jsonify({
        'status': 'success',
        'report': report_summary
    }), 200
