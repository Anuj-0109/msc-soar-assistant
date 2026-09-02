import datetime
from flask import Blueprint, request, jsonify
from constants import (
    ANALYST_IDENTITY,
    VALID_INCIDENT_STATUSES,
    VALID_SEVERITIES,
)
from models.database import get_db_connection

incidents_bp = Blueprint('incidents_bp', __name__)

def log_timeline_event(conn, incident_id, action_by, description):
    """Helper function to automatically insert an activity timeline event."""
    conn.execute(
        'INSERT INTO timeline_events (incident_id, action_by, action_description) VALUES (?, ?, ?)',
        (incident_id, action_by, description)
    )

# ---------------------------------------------------------
# 1. CREATE INCIDENT
# ---------------------------------------------------------
@incidents_bp.route('/api/incidents', methods=['POST'])
def create_incident():
    """Creates a new incident and logs the creation event in the timeline."""
    data = request.get_json() or {}
    
    title = data.get('title')
    description = data.get('description', '')
    ioc_value = data.get('ioc_value', '')
    ioc_type = data.get('ioc_type', 'UNKNOWN').upper()
    severity = data.get('severity', 'MEDIUM').upper()
    risk_score = data.get('risk_score', 0)
    assigned_analyst = ANALYST_IDENTITY

    if severity not in VALID_SEVERITIES:
        return jsonify({
            'status': 'error',
            'message': 'Invalid incident severity.'
        }), 400

    if not title:
        return jsonify({'message': 'Incident title is required!'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO incidents (title, description, ioc_value, ioc_type, severity, risk_score, status, assigned_analyst)
        VALUES (?, ?, ?, ?, ?, ?, 'OPEN', ?)
    ''', (title, description, ioc_value, ioc_type, severity, risk_score, assigned_analyst))
    
    incident_id = cursor.lastrowid

    # Add initial timeline event
    log_timeline_event(conn, incident_id, ANALYST_IDENTITY, f"Incident created with severity {severity}.")
    if ioc_value:
        log_timeline_event(conn, incident_id, ANALYST_IDENTITY, f"Associated IOC added: {ioc_value} ({ioc_type})")

    conn.commit()
    conn.close()

    return jsonify({
        'status': 'success',
        'message': 'Incident created successfully',
        'incident_id': incident_id
    }), 201


# ---------------------------------------------------------
# 2. LIST / SEARCH / FILTER INCIDENTS
# ---------------------------------------------------------
@incidents_bp.route('/api/incidents', methods=['GET'])
def list_incidents():
    """Lists incidents with optional search, filtering by status/severity, and sorting."""
    status_filter = request.args.get('status')
    severity_filter = request.args.get('severity')
    search_query = request.args.get('search')
    sort_by = request.args.get('sort', 'created_at') # created_at, risk_score, severity
    order = request.args.get('order', 'DESC')

    if status_filter and status_filter.upper() not in VALID_INCIDENT_STATUSES:
        return jsonify({
            'status': 'error',
            'message': 'Invalid incident status filter.'
        }), 400

    if severity_filter and severity_filter.upper() not in VALID_SEVERITIES:
        return jsonify({
            'status': 'error',
            'message': 'Invalid severity filter.'
        }), 400

    query = "SELECT * FROM incidents WHERE 1=1"
    params = []

    if status_filter:
        query += " AND status = ?"
        params.append(status_filter.upper())
    
    if severity_filter:
        query += " AND severity = ?"
        params.append(severity_filter.upper())

    if search_query:
        query += " AND (title LIKE ? OR description LIKE ? OR ioc_value LIKE ?)"
        wildcard = f"%{search_query}%"
        params.extend([wildcard, wildcard, wildcard])

    # Dynamic sorting safety check
    valid_sorts = ['created_at', 'updated_at', 'risk_score', 'severity', 'status']
    if sort_by not in valid_sorts:
        sort_by = 'created_at'
    
    query += f" ORDER BY {sort_by} {'ASC' if order.upper() == 'ASC' else 'DESC'}"

    conn = get_db_connection()
    incidents = conn.execute(query, params).fetchall()
    conn.close()

    return jsonify({
        'status': 'success',
        'count': len(incidents),
        'incidents': [dict(row) for row in incidents]
    }), 200


# ---------------------------------------------------------
# 3. GET SINGLE INCIDENT DETAILS & TIMELINE
# ---------------------------------------------------------
@incidents_bp.route('/api/incidents/<int:incident_id>', methods=['GET'])
def get_incident_details(incident_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM incidents WHERE id = ?', (incident_id,))
    incident_row = cursor.fetchone()

    if not incident_row:
        conn.close()
        return jsonify({'status': 'error', 'message': f'Incident #{incident_id} not found'}), 404

    incident = {
        'id': incident_row['id'],
        'title': incident_row['title'],
        'description': incident_row['description'],
        'ioc_value': incident_row['ioc_value'],
        'ioc_type': incident_row['ioc_type'],
        'severity': incident_row['severity'],
        'risk_score': incident_row['risk_score'],
        'status': incident_row['status'],
        'assigned_analyst': incident_row['assigned_analyst'],
        'mitre_tactic': incident_row['mitre_tactic'],
        'mitre_technique': incident_row['mitre_technique'],
        'created_at': incident_row['created_at'],
        'updated_at': incident_row['updated_at']
    }

    cursor.execute('SELECT * FROM timeline_events WHERE incident_id = ? ORDER BY timestamp ASC', (incident_id,))
    timeline = [dict(row) for row in cursor.fetchall()]

    cursor.execute('SELECT * FROM comments WHERE incident_id = ? ORDER BY created_at ASC', (incident_id,))
    comments = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return jsonify({
        'status': 'success',
        'incident': incident,
        'timeline': timeline,
        'comments': comments
    }), 200

# ---------------------------------------------------------
# 4. UPDATE INCIDENT / UPDATE STATUS / ASSIGN
# ---------------------------------------------------------
@incidents_bp.route('/api/incidents/<int:incident_id>', methods=['PUT'])
def update_incident(incident_id):
    """Updates status, analyst assignment, severity, or risk score and logs to timeline."""
    data = request.get_json() or {}
    
    conn = get_db_connection()
    incident = conn.execute('SELECT * FROM incidents WHERE id = ?', (incident_id,)).fetchone()
    if not incident:
        conn.close()
        return jsonify({'message': 'Incident not found!'}), 404

    current_data = dict(incident)
    new_status = data.get('status', current_data['status']).upper()
    new_analyst = ANALYST_IDENTITY
    new_severity = data.get('severity', current_data['severity']).upper()
    new_risk_score = data.get('risk_score', current_data['risk_score'])
    new_description = data.get('description', current_data['description'])

    if new_status not in VALID_INCIDENT_STATUSES:
        conn.close()
        return jsonify({
            'status': 'error',
            'message': 'Invalid incident status.'
        }), 400

    if new_severity not in VALID_SEVERITIES:
        conn.close()
        return jsonify({
            'status': 'error',
            'message': 'Invalid incident severity.'
        }), 400

    # Log specific timeline updates
    if new_status != current_data['status']:
        log_timeline_event(
            conn, incident_id, ANALYST_IDENTITY,
            f"Status changed from {current_data['status']} to {new_status}"
        )
    
    if new_analyst != current_data['assigned_analyst']:
        log_timeline_event(
            conn, incident_id, ANALYST_IDENTITY,
            f"Assigned analyst updated to {new_analyst}"
        )

    if new_severity != current_data['severity']:
        log_timeline_event(
            conn, incident_id, ANALYST_IDENTITY,
            f"Severity reclassified from {current_data['severity']} to {new_severity}"
        )

    conn.execute('''
        UPDATE incidents
        SET status = ?, assigned_analyst = ?, severity = ?, risk_score = ?, description = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (new_status, new_analyst, new_severity, new_risk_score, new_description, incident_id))

    conn.commit()
    conn.close()

    return jsonify({'status': 'success', 'message': f'Incident #{incident_id} updated successfully.'}), 200


# ---------------------------------------------------------
# 5. ADD COMMENT TO INCIDENT
# ---------------------------------------------------------
@incidents_bp.route('/api/incidents/<int:incident_id>/comments', methods=['POST'])
def add_comment(incident_id):
    """Attaches an analyst investigation comment and logs it to the activity timeline."""
    data = request.get_json() or {}
    comment_text = data.get('comment')

    if not comment_text:
        return jsonify({'message': 'Comment text cannot be empty!'}), 400

    conn = get_db_connection()
    incident = conn.execute('SELECT id FROM incidents WHERE id = ?', (incident_id,)).fetchone()
    if not incident:
        conn.close()
        return jsonify({'message': 'Incident not found!'}), 404

    conn.execute(
        'INSERT INTO comments (incident_id, author, comment_text) VALUES (?, ?, ?)',
        (incident_id, ANALYST_IDENTITY, comment_text)
    )
    
    log_timeline_event(
        conn, incident_id, ANALYST_IDENTITY,
        f"Analyst added investigation comment: \"{comment_text[:50]}...\"" if len(comment_text) > 50 else f"Analyst added comment: \"{comment_text}\""
    )

    conn.commit()
    conn.close()

    return jsonify({'status': 'success', 'message': 'Comment added successfully.'}), 201


# ---------------------------------------------------------
# 6. DELETE INCIDENT
# ---------------------------------------------------------
@incidents_bp.route('/api/incidents/<int:incident_id>', methods=['DELETE'])
def delete_incident(incident_id):
    """Deletes an incident record along with its associated timeline and comments."""
    conn = get_db_connection()
    incident = conn.execute('SELECT id FROM incidents WHERE id = ?', (incident_id,)).fetchone()
    if not incident:
        conn.close()
        return jsonify({'message': 'Incident not found!'}), 404

    conn.execute('DELETE FROM incidents WHERE id = ?', (incident_id,))
    conn.commit()
    conn.close()

    return jsonify({'status': 'success', 'message': f'Incident #{incident_id} deleted.'}), 200
