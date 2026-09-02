"use strict";

let supervisorAnalysis = null;
let supervisorIncidents = [];
let supervisorSelectedIncident = null;

function demoEscape(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function demoStatusText(ok, text) {
    return `<span class="${ok ? "demo-success" : "demo-failure"}">${ok ? "PASS" : "FAIL"}</span> — ${demoEscape(text)}`;
}

function demoNumber(value) {
    if (value === null || value === undefined || value === "") return "-";
    const number = Number(value);
    return Number.isFinite(number) ? number.toFixed(3).replace(/0+$/, "").replace(/\.$/, "") : demoEscape(value);
}

function setDemoIoc(type, value) {
    document.getElementById("demoIocType").value = type;
    document.getElementById("demoIocValue").value = value;
    document.getElementById("demoIocResult").textContent = `Ready to analyse ${value}.`;
}

function demoSources(analysis) {
    const sources = analysis.sources || analysis.provider_results || {};
    if (Array.isArray(sources)) {
        return sources.map((item, index) => [item.source || item.name || `Source ${index + 1}`, item]);
    }
    return Object.entries(sources);
}

async function loadSupervisorStatus() {
    const threat = document.getElementById("demoThreatMode");
    const containment = document.getElementById("demoContainmentMode");
    const database = document.getElementById("demoDatabaseStatus");
    const rasa = document.getElementById("demoRasaStatus");
    try {
        const response = await fetch("/api/demo/status");
        const data = await response.json();
        if (!response.ok || data.status !== "success") throw new Error(data.message || "Status unavailable.");
        threat.textContent = data.modes.threat_intelligence;
        containment.textContent = data.modes.playbook_containment;
        threat.className = `demo-mode-value ${data.modes.threat_intelligence === "LIVE" ? "demo-success" : ""}`;
        containment.className = `demo-mode-value ${data.modes.playbook_containment === "LIVE" ? "demo-failure" : ""}`;
        database.innerHTML = data.system.database.ok ? '<span class="demo-success">ONLINE</span>' : '<span class="demo-failure">OFFLINE</span>';
        const rasaOk = data.system.rasa.ok && data.system.action_server.ok;
        rasa.innerHTML = rasaOk ? '<span class="demo-success">ONLINE</span>' : '<span class="demo-failure">CHECK SERVICES</span>';
    } catch (error) {
        threat.textContent = "ERROR";
        containment.textContent = "ERROR";
        database.textContent = "ERROR";
        rasa.textContent = error.message;
    }
}

async function analyseDemoIoc() {
    const resultBox = document.getElementById("demoIocResult");
    const createButton = document.getElementById("demoCreateIncidentButton");
    resultBox.textContent = "Running threat-intelligence analysis...";
    createButton.disabled = true;
    supervisorAnalysis = null;
    try {
        const response = await fetch("/api/demo/analyze-ioc", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                ioc_type: document.getElementById("demoIocType").value,
                value: document.getElementById("demoIocValue").value,
            }),
        });
        const data = await response.json();
        if (!response.ok || data.status !== "success") throw new Error(data.message || "Analysis failed.");
        supervisorAnalysis = data;
        const analysis = data.analysis || {};
        const sourceCards = demoSources(analysis).map(([name, source]) => {
            const status = source.status || source.source_status || source.mode || "UNKNOWN";
            const verdict = source.verdict || source.result || source.message || "No summary";
            return `<div class="demo-provider"><strong>${demoEscape(name)}</strong><span>${demoEscape(status)}</span><br><small>${demoEscape(verdict)}</small></div>`;
        }).join("");
        resultBox.innerHTML = `
            <div><strong>${demoEscape(data.ioc.type)}:</strong> ${demoEscape(data.ioc.value)}</div>
            <div style="margin-top:6px"><strong>Risk:</strong> ${demoEscape(analysis.risk_score ?? 0)}/100 — ${demoEscape(analysis.severity || "UNKNOWN")}</div>
            <div style="margin-top:6px"><strong>Evidence:</strong> ${demoEscape(analysis.evidence_mode || "NONE")} / ${demoEscape(analysis.overall_status || "UNKNOWN")}</div>
            <div style="margin-top:6px"><strong>Recommendation:</strong> ${demoEscape(analysis.recommendation || "No recommendation returned.")}</div>
            <div style="margin-top:6px"><strong>Containment:</strong> ${demoEscape(data.containment_capability.control)} — ${demoEscape(data.containment_capability.message)}</div>
            <div class="demo-provider-grid">${sourceCards || '<div class="demo-muted">No provider-level results were returned.</div>'}</div>
        `;
        createButton.disabled = false;
    } catch (error) {
        resultBox.innerHTML = `<span class="demo-failure">${demoEscape(error.message)}</span>`;
    }
}

async function createIncidentFromDemoAnalysis() {
    const resultBox = document.getElementById("demoIocResult");
    if (!supervisorAnalysis) {
        resultBox.textContent = "Analyse an IOC before creating an incident.";
        return;
    }
    const analysis = supervisorAnalysis.analysis || {};
    const ioc = supervisorAnalysis.ioc;
    const title = window.prompt("Incident title", `Supervisor demonstration: ${ioc.value}`);
    if (title === null) return;
    const description = window.prompt("Incident description", `Dashboard-created ${ioc.type} investigation using live threat-intelligence evidence.`);
    if (description === null) return;
    try {
        const response = await fetch("/api/demo/incidents/from-analysis", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                title,
                description,
                ioc_value: ioc.value,
                ioc_type: ioc.type,
                risk_score: analysis.risk_score || 0,
                severity: analysis.severity || "MEDIUM",
            }),
        });
        const data = await response.json();
        if (!response.ok || data.status !== "success") throw new Error(data.message || "Incident creation failed.");
        resultBox.innerHTML += `<div class="demo-success" style="margin-top:10px">Incident #${data.incident_id} created successfully.</div>`;
        await fetchSupervisorIncidents(data.incident_id);
        if (typeof refreshPlaybookPanel === "function") refreshPlaybookPanel();
        if (typeof refreshDashboard === "function") refreshDashboard();
    } catch (error) {
        resultBox.innerHTML += `<div class="demo-failure" style="margin-top:10px">${demoEscape(error.message)}</div>`;
    }
}

async function ingestDemoIdsAlert() {
    const resultBox = document.getElementById("demoIdsResult");
    resultBox.textContent = "Ingesting controlled IDS event...";
    try {
        const response = await fetch("/api/demo/ingest/suricata", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                src_ip: document.getElementById("demoIdsSourceIp").value,
                dest_ip: document.getElementById("demoIdsDestinationIp").value,
                signature: document.getElementById("demoIdsSignature").value,
                category: document.getElementById("demoIdsCategory").value,
                ids_severity: Number(document.getElementById("demoIdsSeverity").value),
            }),
        });
        const data = await response.json();
        if (!response.ok || data.status !== "success") throw new Error(data.message || "IDS ingestion failed.");
        resultBox.innerHTML = `<span class="demo-success">Incident #${data.incident_id} created.</span><br>IOC ${demoEscape(data.ioc_value)} · Severity ${demoEscape(data.severity)} · Risk ${demoEscape(data.risk_score)}/100`;
        await fetchSupervisorIncidents(data.incident_id);
        if (typeof refreshPlaybookPanel === "function") refreshPlaybookPanel();
        if (typeof refreshDashboard === "function") refreshDashboard();
    } catch (error) {
        resultBox.innerHTML = `<span class="demo-failure">${demoEscape(error.message)}</span>`;
    }
}

async function fetchSupervisorIncidents(preferredId = null) {
    const select = document.getElementById("demoIncidentSelect");
    try {
        const response = await fetch("/api/demo/incidents?limit=150");
        const data = await response.json();
        if (!response.ok || data.status !== "success") throw new Error(data.message || "Incident list failed.");
        const previous = preferredId ? String(preferredId) : select.value;
        supervisorIncidents = data.incidents || [];
        select.innerHTML = supervisorIncidents.length
            ? supervisorIncidents.map((incident) => `<option value="${Number(incident.id)}">#${Number(incident.id)} [${demoEscape(incident.status)}/${demoEscape(incident.severity)}] ${demoEscape(incident.title)} — ${demoEscape(incident.ioc_value || "No IOC")}</option>`).join("")
            : '<option value="">No incidents available</option>';
        if (supervisorIncidents.some((item) => String(item.id) === previous)) select.value = previous;
        await loadSelectedDemoIncident();
    } catch (error) {
        select.innerHTML = `<option value="">${demoEscape(error.message)}</option>`;
    }
}

function selectedDemoIncidentId() {
    return Number(document.getElementById("demoIncidentSelect").value || 0);
}

async function loadSelectedDemoIncident() {
    const incidentId = selectedDemoIncidentId();
    const box = document.getElementById("demoIncidentDetails");
    supervisorSelectedIncident = null;
    if (!incidentId) {
        box.textContent = "No incident selected.";
        return;
    }
    box.textContent = `Loading incident #${incidentId}...`;
    try {
        const response = await fetch(`/api/demo/incidents/${incidentId}`);
        const data = await response.json();
        if (!response.ok || data.status !== "success") throw new Error(data.message || "Incident retrieval failed.");
        supervisorSelectedIncident = data;
        const incident = data.incident;
        const timeline = (data.timeline || []).slice(-8).map((event) => `<tr><td>${demoEscape(event.timestamp || "")}</td><td>${demoEscape(event.action_by || "")}</td><td>${demoEscape(event.action_description || "")}</td></tr>`).join("");
        const comments = (data.comments || []).slice(-5).map((comment) => `<li>${demoEscape(comment.comment || comment.comment_text || comment.content || "")}</li>`).join("");
        box.innerHTML = `
            <div><strong>#${Number(incident.id)} ${demoEscape(incident.title)}</strong></div>
            <div style="margin-top:6px">${demoEscape(incident.ioc_type)}: <code>${demoEscape(incident.ioc_value || "-")}</code></div>
            <div style="margin-top:6px">Status <strong>${demoEscape(incident.status)}</strong> · Severity <strong>${demoEscape(incident.severity)}</strong> · Risk <strong>${demoEscape(incident.risk_score)}/100</strong></div>
            <div style="margin-top:6px"><strong>Containment capability:</strong> ${demoEscape(data.containment_capability.control)} — ${demoEscape(data.containment_capability.message)}</div>
            <div style="margin-top:10px"><strong>Recent comments</strong><ul>${comments || '<li>No comments recorded.</li>'}</ul></div>
            <div class="demo-table-scroll"><table class="demo-table"><thead><tr><th>Time</th><th>Actor</th><th>Timeline event</th></tr></thead><tbody>${timeline || '<tr><td colspan="3">No timeline events recorded.</td></tr>'}</tbody></table></div>
        `;
    } catch (error) {
        box.innerHTML = `<span class="demo-failure">${demoEscape(error.message)}</span>`;
    }
}

async function updateDemoIncidentStatus(status) {
    const incidentId = selectedDemoIncidentId();
    if (!incidentId) return window.alert("Select an incident first.");
    try {
        const response = await fetch(`/api/demo/incidents/${incidentId}/status`, {
            method: "PUT",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({status}),
        });
        const data = await response.json();
        if (!response.ok || data.status !== "success") throw new Error(data.message || "Status update failed.");
        await fetchSupervisorIncidents(incidentId);
        if (typeof refreshPlaybookPanel === "function") refreshPlaybookPanel();
    } catch (error) {
        window.alert(error.message);
    }
}

async function addDemoIncidentComment() {
    const incidentId = selectedDemoIncidentId();
    const input = document.getElementById("demoIncidentComment");
    const comment = input.value.trim();
    if (!incidentId) return window.alert("Select an incident first.");
    if (!comment) return window.alert("Enter a comment first.");
    try {
        const response = await fetch(`/api/demo/incidents/${incidentId}/comments`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({comment}),
        });
        const data = await response.json();
        if (!response.ok || data.status !== "success") throw new Error(data.message || "Comment failed.");
        input.value = "";
        await loadSelectedDemoIncident();
    } catch (error) {
        window.alert(error.message);
    }
}

function ensureWorkspaceActionNotice() {
    let notice = document.getElementById("demoActionNotice");
    if (notice) return notice;

    notice = document.createElement("div");
    notice.id = "demoActionNotice";
    notice.className = "demo-action-notice";
    notice.setAttribute("role", "status");
    notice.setAttribute("aria-live", "polite");

    const details = document.getElementById("demoIncidentDetails");
    if (details && details.parentNode) {
        details.parentNode.insertBefore(notice, details);
    } else {
        document.body.appendChild(notice);
    }
    return notice;
}

function showWorkspaceActionNotice(message, kind = "info") {
    const notice = ensureWorkspaceActionNotice();
    notice.className = `demo-action-notice demo-action-${kind}`;
    notice.textContent = message;
    notice.hidden = false;
}

function requestWorkspaceUfwConfirmation(action, incident) {
    return new Promise((resolve) => {
        const existing = document.getElementById("demoUfwConfirmationOverlay");
        if (existing) existing.remove();

        const isBlock = action === "contain";
        const operation = isBlock ? "create" : "remove";
        const label = isBlock ? "Block IP" : "Unblock IP";

        const overlay = document.createElement("div");
        overlay.id = "demoUfwConfirmationOverlay";
        overlay.className = "demo-confirm-overlay";
        overlay.innerHTML = `
            <div class="demo-confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="demoConfirmTitle">
                <div class="demo-confirm-warning">LIVE UFW ACTION</div>
                <h3 id="demoConfirmTitle">${label}</h3>
                <p>This will <strong>${operation}</strong> a real firewall rule for:</p>
                <code>${demoEscape(incident.ioc_value)}</code>
                <p class="demo-confirm-note">
                    Continue only when this is a controlled IPv4 target in your local VM.
                </p>
                <div class="demo-confirm-actions">
                    <button type="button" class="btn demo-btn" id="demoCancelUfwAction">Cancel</button>
                    <button type="button" class="btn demo-btn demo-btn-live" id="demoConfirmUfwAction">
                        Confirm ${label}
                    </button>
                </div>
            </div>
        `;

        document.body.appendChild(overlay);

        const finish = (answer) => {
            overlay.remove();
            resolve(answer);
        };

        document.getElementById("demoCancelUfwAction").onclick = () => finish(false);
        document.getElementById("demoConfirmUfwAction").onclick = () => finish(true);
        overlay.addEventListener("click", (event) => {
            if (event.target === overlay) finish(false);
        });

        const escapeHandler = (event) => {
            if (event.key === "Escape") {
                document.removeEventListener("keydown", escapeHandler);
                finish(false);
            }
        };
        document.addEventListener("keydown", escapeHandler);
    });
}

async function executeLiveIncidentAction(action) {
    const incidentId = selectedDemoIncidentId();

    if (!incidentId || !supervisorSelectedIncident) {
        showWorkspaceActionNotice(
            "Select an incident and wait for its details to load before using live UFW.",
            "error"
        );
        return;
    }

    const incident = supervisorSelectedIncident.incident;

    if (String(incident.ioc_type).toUpperCase() !== "IP") {
        showWorkspaceActionNotice(
            supervisorSelectedIncident.containment_capability.message,
            "error"
        );
        return;
    }

    const confirmed = await requestWorkspaceUfwConfirmation(action, incident);
    if (!confirmed) {
        showWorkspaceActionNotice("Live UFW action cancelled.", "info");
        return;
    }

    const actionLabel = action === "contain" ? "blocking" : "unblocking";
    showWorkspaceActionNotice(
        `Live UFW ${actionLabel} request is being processed for ${incident.ioc_value}...`,
        "working"
    );

    try {
        const response = await fetch(`/api/demo/incidents/${incidentId}/${action}`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-cache",
            },
            cache: "no-store",
            body: JSON.stringify({confirm_live: true}),
        });

        let data = {};
        try {
            data = await response.json();
        } catch (_) {
            data = {
                status: "error",
                message: `The server returned HTTP ${response.status} without JSON output.`,
            };
        }

        if (!response.ok || data.status !== "success") {
            const details = data.message || "The UFW action failed.";
            const executionStatus = data.execution_status || `HTTP ${response.status}`;
            throw new Error(`${executionStatus}: ${details}`);
        }

        showWorkspaceActionNotice(
            `${data.execution_status}: ${data.message}`,
            "success"
        );

        await Promise.all([
            fetchSupervisorIncidents(incidentId),
            refreshDemoUfwRules(),
        ]);

        if (typeof fetchUfwRules === "function") {
            fetchUfwRules();
        }

        if (typeof refreshPlaybookPanel === "function") {
            refreshPlaybookPanel();
        }
    } catch (error) {
        showWorkspaceActionNotice(
            `${error.message} Check the Live UFW Rules panel. If it reports that a password is required, refresh sudo authorisation in the Flask terminal.`,
            "error"
        );
        await refreshDemoUfwRules();
    }
}

function liveContainSelectedIncident() {
    return executeLiveIncidentAction("contain");
}

function liveUnblockSelectedIncident() {
    return executeLiveIncidentAction("unblock");
}

async function refreshDemoUfwRules() {
    const output = document.getElementById("demoUfwOutput");
    output.textContent = "Reading live UFW rules...";

    try {
        const response = await fetch("/api/demo/ufw-rules", {
            cache: "no-store",
            headers: {"Cache-Control": "no-cache"},
        });

        let data = {};
        try {
            data = await response.json();
        } catch (_) {
            data = {
                status: "error",
                message: `The server returned HTTP ${response.status} without JSON output.`,
            };
        }

        const message = data.output || data.message || "No UFW output returned.";

        if (!response.ok || data.status !== "success") {
            output.textContent =
                `UFW NOT READY\n${message}\n\n` +
                "Common cause: the Flask process no longer has non-interactive sudo authorisation.";
            output.classList.add("demo-ufw-error");
            return;
        }

        output.classList.remove("demo-ufw-error");
        output.textContent = message;
    } catch (error) {
        output.classList.add("demo-ufw-error");
        output.textContent = `UFW STATUS ERROR\n${error.message}`;
    }
}

function downloadDemoIncidentReport() {
    const incidentId = selectedDemoIncidentId();
    if (!incidentId) return window.alert("Select an incident first.");
    document.getElementById("demoReportStatus").textContent = `Generating report for incident #${incidentId}...`;
    window.location = `/api/intelligence/reports/incident/${incidentId}`;
}

async function runSupervisorValidation() {
    const summary = document.getElementById("demoValidationSummary");
    const checks = document.getElementById("demoValidationChecks");
    summary.textContent = "Running safe system checks...";
    checks.innerHTML = "";
    try {
        const response = await fetch("/api/demo/validation");
        const data = await response.json();
        if (!response.ok || data.status !== "success") throw new Error(data.message || "Validation failed.");
        summary.innerHTML = `<strong>${demoEscape(data.overall)}</strong> — ${data.passed} passed, ${data.failed} require attention. Checked ${demoEscape(data.checked_at)} UTC.`;
        checks.innerHTML = (data.checks || []).map((check) => `<div class="demo-check"><strong>${demoEscape(check.name)}</strong>${demoStatusText(check.ok, check.message)}</div>`).join("");
    } catch (error) {
        summary.innerHTML = `<span class="demo-failure">${demoEscape(error.message)}</span>`;
    }
}

async function loadSupervisorEvaluation() {
    const summary = document.getElementById("demoEvaluationSummary");
    const metrics = document.getElementById("demoEvaluationMetrics");
    summary.textContent = "Loading saved evaluation results...";
    metrics.innerHTML = "";
    try {
        const response = await fetch("/api/demo/evaluation");
        const data = await response.json();
        if (!response.ok || data.status !== "success") throw new Error(data.message || "Evaluation failed.");
        const evaluation = data.evaluation;
        summary.innerHTML = evaluation.available
            ? `<span class="demo-success">AVAILABLE</span> — ${demoEscape(evaluation.source_directory)}. These are saved, reproducible Rasa results; no expensive retraining occurs during the live demonstration.`
            : `<span class="demo-failure">UNAVAILABLE</span> — ${demoEscape(evaluation.message)}`;
        const labels = {
            accuracy: "Accuracy",
            macro_precision: "Macro precision",
            macro_recall: "Macro recall",
            macro_f1: "Macro F1",
            weighted_f1: "Weighted F1",
            test_examples: "Test examples",
            error_examples: "Error examples",
        };
        metrics.innerHTML = Object.entries(labels).map(([key, label]) => `<div class="demo-metric"><strong>${label}</strong>${demoNumber(evaluation.metrics?.[key])}</div>`).join("");
    } catch (error) {
        summary.innerHTML = `<span class="demo-failure">${demoEscape(error.message)}</span>`;
    }
}

function showDemoEvaluationImage(kind) {
    const image = document.getElementById("demoEvaluationImage");
    image.style.display = "block";
    image.src = `/api/demo/evaluation/artifact/${kind}?t=${Date.now()}`;
}

async function refreshSupervisorDemo() {
    await Promise.allSettled([
        loadSupervisorStatus(),
        fetchSupervisorIncidents(),
        refreshDemoUfwRules(),
        loadSupervisorEvaluation(),
    ]);
}

document.addEventListener("DOMContentLoaded", () => {
    refreshSupervisorDemo();
});
