from flask import Flask, render_template, jsonify, send_file
import subprocess
import audit_logger
from models.database import init_expanded_db
from services.playbook_engine import ensure_playbook_schema
from blueprints.incidents import incidents_bp
from blueprints.playbooks import playbooks_bp
from blueprints.ingestion import ingestion_bp
from blueprints.chat import chat_bp
from blueprints.analytics import analytics_bp  
from blueprints.supervisor_demo import supervisor_demo_bp
from blueprints.intelligence_reporting import intelligence_reporting_bp

app = Flask(__name__)

# 1. Initialize Expanded Database on startup
init_expanded_db()
ensure_playbook_schema()
audit_logger.init_db()

# 2. Register Blueprints
app.register_blueprint(incidents_bp)
app.register_blueprint(playbooks_bp)
app.register_blueprint(ingestion_bp)
app.register_blueprint(chat_bp)
app.register_blueprint(analytics_bp)  
app.register_blueprint(supervisor_demo_bp)
app.register_blueprint(intelligence_reporting_bp)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/ufw-rules", methods=["GET"])
def get_ufw_rules():
    try:
        result = subprocess.run(["sudo", "ufw", "status", "numbered"], capture_output=True, text=True, timeout=5)
        return jsonify({"status": "success", "output": result.stdout})
    except Exception as e:
        return jsonify({"status": "error", "output": f"UFW check failed: {str(e)}"})

@app.route("/api/download-report", methods=["GET"])
def download_report():
    try:
        pdf_filename = audit_logger.generate_pdf_report()
        return send_file(pdf_filename, as_attachment=True)
    except Exception as e:
        return jsonify({"error": f"Failed to generate PDF: {str(e)}"}), 500

if __name__ == '__main__':
    init_expanded_db()
    app.run(host='127.0.0.1', port=5000, debug=True)
