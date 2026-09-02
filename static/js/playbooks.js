"use strict";

let globalPlaybooks = [];
let globalOpenIncidents = [];
let globalPlaybookExecutions = [];

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function playbookStatusClass(value) {
    const normalised = String(value || "UNKNOWN")
        .toLowerCase()
        .replaceAll("_", "-")
        .replaceAll(" ", "-");

    const supported = new Set([
        "pending",
        "awaiting-approval",
        "success",
        "approved",
        "live",
        "failed",
        "rejected",
        "error",
        "simulated",
        "simulation",
        "disabled",
        "not-executed",
        "not-requested",
        "unknown",
    ]);

    return supported.has(normalised)
        ? `status-${normalised}`
        : "status-unknown";
}

function playbookStatusBadge(value) {
    const safeValue = escapeHtml(value || "UNKNOWN");
    return `<span class="status-badge ${playbookStatusClass(value)}">${safeValue}</span>`;
}

function playbookFormatDate(value) {
    if (!value) return "-";

    const rawValue = String(value);
    const hasTimezone = /([zZ]|[+-]\d{2}:\d{2})$/.test(rawValue);
    const normalised = rawValue.replace(" ", "T") + (hasTimezone ? "" : "Z");
    const parsed = new Date(normalised);

    if (Number.isNaN(parsed.getTime())) {
        return escapeHtml(rawValue);
    }

    return escapeHtml(parsed.toLocaleString());
}

async function fetchPlaybooks() {
    const select = document.getElementById("playbookSelect");

    try {
        const res = await fetch("/api/playbooks");
        const data = await res.json();

        if (!res.ok || data.status !== "success") {
            throw new Error(data.message || "Unable to load playbooks.");
        }

        const previousSelection = select.value;
        globalPlaybooks = data.playbooks || [];
        select.innerHTML = "";

        if (globalPlaybooks.length === 0) {
            select.innerHTML = '<option value="">No playbooks available</option>';
            renderSelectedPlaybook();
            return;
        }

        globalPlaybooks.forEach((playbook) => {
            const option = document.createElement("option");
            option.value = playbook.id;
            option.textContent = `${playbook.name} (${playbook.enabled ? "Enabled" : "Disabled"})`;
            select.appendChild(option);
        });

        if (globalPlaybooks.some((item) => String(item.id) === previousSelection)) {
            select.value = previousSelection;
        } else {
            const preferred = globalPlaybooks.find((item) => item.enabled) || globalPlaybooks[0];
            select.value = String(preferred.id);
        }

        renderSelectedPlaybook();
    } catch (error) {
        select.innerHTML = '<option value="">Playbook API unavailable</option>';
        document.getElementById("playbookDetails").textContent = error.message;
    }
}

function renderSelectedPlaybook() {
    const select = document.getElementById("playbookSelect");
    const details = document.getElementById("playbookDetails");
    const toggleButton = document.getElementById("playbookToggleButton");
    const playbook = globalPlaybooks.find((item) => String(item.id) === select.value);

    if (!playbook) {
        details.textContent = "No playbook is selected.";
        toggleButton.disabled = true;
        return;
    }

    const steps = (playbook.workflow || []).map((step, index) => `
        <div class="workflow-step">
            <div>
                <div class="workflow-step-name">${index + 1}. ${escapeHtml(step.name)}</div>
                <div class="workflow-step-meta">${escapeHtml(step.action)}</div>
            </div>
            <div>${step.requires_approval ? playbookStatusBadge("PENDING") : playbookStatusBadge("APPROVED")}</div>
        </div>
    `).join("");

    details.innerHTML = `
        <div><strong>${escapeHtml(playbook.name)}</strong> ${playbook.enabled ? playbookStatusBadge("SUCCESS") : playbookStatusBadge("DISABLED")}</div>
        <div style="margin-top: 8px;">${escapeHtml(playbook.description || "No description supplied.")}</div>
        <div style="margin-top: 8px;"><strong>Trigger:</strong> ${escapeHtml(playbook.trigger_condition || "-")}</div>
        <div style="margin-top: 8px;"><strong>Analyst approval:</strong> ${playbook.requires_approval ? "Required" : "Not required"}</div>
        <div class="workflow-list">${steps || "<div>No workflow steps configured.</div>"}</div>
    `;

    toggleButton.disabled = false;
    toggleButton.textContent = playbook.enabled ? "Disable Playbook" : "Enable Playbook";
}

async function toggleSelectedPlaybook() {
    const select = document.getElementById("playbookSelect");
    const playbook = globalPlaybooks.find((item) => String(item.id) === select.value);

    if (!playbook) return;

    const statusBox = document.getElementById("playbookRequestStatus");
    statusBox.textContent = `${playbook.enabled ? "Disabling" : "Enabling"} ${playbook.name}...`;

    try {
        const res = await fetch(`/api/playbooks/${playbook.id}/enabled`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ enabled: !playbook.enabled }),
        });

        const data = await res.json();

        if (!res.ok || data.status !== "success") {
            throw new Error(data.message || "Unable to update playbook.");
        }

        statusBox.textContent = `✓ ${data.playbook.name} is now ${data.playbook.enabled ? "enabled" : "disabled"}.`;
        await fetchPlaybooks();
    } catch (error) {
        statusBox.textContent = `❌ ${error.message}`;
    }
}

async function fetchPlaybookIncidents() {
    const select = document.getElementById("playbookIncidentSelect");

    try {
        const res = await fetch("/api/incidents?order=DESC");
        const data = await res.json();

        if (!res.ok || data.status !== "success") {
            throw new Error(data.message || "Unable to load incidents.");
        }

        globalOpenIncidents = (data.incidents || []).filter((incident) =>
            incident.status !== "CLOSED" && String(incident.ioc_value || "").trim() !== ""
        );

        select.innerHTML = "";

        if (globalOpenIncidents.length === 0) {
            select.innerHTML = '<option value="">No open incidents with IOCs</option>';
            return;
        }

        globalOpenIncidents.forEach((incident) => {
            const option = document.createElement("option");
            option.value = incident.id;
            option.textContent = `#${incident.id} [${incident.status}/${incident.severity}] ${incident.title} — ${incident.ioc_value}`;
            select.appendChild(option);
        });
    } catch (error) {
        select.innerHTML = '<option value="">Incident API unavailable</option>';
        document.getElementById("playbookRequestStatus").textContent = `❌ ${error.message}`;
    }
}

async function requestPlaybookExecution() {
    const playbookId = Number(document.getElementById("playbookSelect").value);
    const incidentId = Number(document.getElementById("playbookIncidentSelect").value);
    const statusBox = document.getElementById("playbookRequestStatus");

    if (!playbookId || !incidentId) {
        statusBox.textContent = "❌ Select an enabled playbook and an open incident.";
        return;
    }

    const playbook = globalPlaybooks.find((item) => item.id === playbookId);

    if (!playbook || !playbook.enabled) {
        statusBox.textContent = "❌ The selected playbook is disabled.";
        return;
    }

    statusBox.textContent = "Creating a pending analyst approval request...";

    try {
        const res = await fetch(`/api/playbooks/${playbookId}/execute`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ incident_id: incidentId }),
        });

        const data = await res.json();

        if (!res.ok || data.status !== "success") {
            throw new Error(data.message || "Unable to request execution.");
        }

        const execution = data.execution;
        statusBox.textContent = `✓ Execution #${execution.id} is ${execution.approval_status}. No firewall action has occurred.`;
        await refreshPlaybookPanel();
    } catch (error) {
        statusBox.textContent = `❌ ${error.message}`;
    }
}

async function fetchPlaybookExecutions() {
    try {
        const res = await fetch("/api/playbook-executions?limit=50");
        const data = await res.json();

        if (!res.ok || data.status !== "success") {
            throw new Error(data.message || "Unable to load executions.");
        }

        globalPlaybookExecutions = data.executions || [];
        renderPendingExecutions();
        renderExecutionHistory();
    } catch (error) {
        document.getElementById("pendingPlaybookTable").innerHTML = `<tr><td colspan="6">${escapeHtml(error.message)}</td></tr>`;
        document.getElementById("playbookHistoryTable").innerHTML = `<tr><td colspan="8">${escapeHtml(error.message)}</td></tr>`;
    }
}

function renderPendingExecutions() {
    const tbody = document.getElementById("pendingPlaybookTable");
    const pending = globalPlaybookExecutions.filter((execution) =>
        execution.status === "PENDING" && execution.approval_status === "PENDING"
    );

    if (pending.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="color: var(--text-muted);">No executions are awaiting analyst approval.</td></tr>';
        return;
    }

    tbody.innerHTML = pending.map((execution) => `
        <tr>
            <td><strong>#${escapeHtml(execution.id)}</strong></td>
            <td>#${escapeHtml(execution.incident_id)} — ${escapeHtml(execution.incident_title || "")}<br><span style="color: var(--text-muted);">${escapeHtml(execution.incident_ioc || "")}</span></td>
            <td>${escapeHtml(execution.playbook_name || "")}</td>
            <td>${playbookStatusBadge(execution.execution_mode)}</td>
            <td>${playbookFormatDate(execution.executed_at)}</td>
            <td>
                <button class="btn playbook-btn-small playbook-btn-approve" onclick="approvePlaybookExecution(${Number(execution.id)})">Approve</button>
                <button class="btn playbook-btn-small playbook-btn-reject" onclick="rejectPlaybookExecution(${Number(execution.id)})">Reject</button>
            </td>
        </tr>
    `).join("");
}

function renderExecutionHistory() {
    const tbody = document.getElementById("playbookHistoryTable");

    if (globalPlaybookExecutions.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="color: var(--text-muted);">No playbook executions have been recorded.</td></tr>';
        return;
    }

    tbody.innerHTML = globalPlaybookExecutions.map((execution) => `
        <tr>
            <td>#${escapeHtml(execution.id)}</td>
            <td>#${escapeHtml(execution.incident_id)} ${escapeHtml(execution.incident_ioc || "")}</td>
            <td>${playbookStatusBadge(execution.status)}</td>
            <td>${playbookStatusBadge(execution.execution_mode)}</td>
            <td>${playbookStatusBadge(execution.approval_status)}</td>
            <td>${playbookStatusBadge(execution.containment_status)}</td>
            <td>${playbookFormatDate(execution.completed_at || execution.executed_at)}</td>
            <td><button class="btn playbook-btn-small" onclick="showPlaybookExecution(${Number(execution.id)})">View Steps</button></td>
        </tr>
    `).join("");
}

async function decidePlaybookExecution(executionId, decision) {
    const statusBox = document.getElementById("playbookRequestStatus");
    statusBox.textContent = `${decision === "approve" ? "Approving and executing" : "Rejecting"} execution #${executionId}...`;

    try {
        const res = await fetch(`/api/playbook-executions/${executionId}/${decision}`, {
            method: "POST",
        });

        const data = await res.json();

        if (!res.ok || data.status !== "success") {
            throw new Error(data.message || `Unable to ${decision} execution.`);
        }

        const execution = data.execution;
        statusBox.textContent = `✓ Execution #${execution.id}: ${execution.status}; containment ${execution.containment_status}.`;
        refreshDashboard();
        await showPlaybookExecution(execution.id);
    } catch (error) {
        statusBox.textContent = `❌ ${error.message}`;
    }
}

function approvePlaybookExecution(executionId) {
    return decidePlaybookExecution(executionId, "approve");
}

function rejectPlaybookExecution(executionId) {
    return decidePlaybookExecution(executionId, "reject");
}

async function showPlaybookExecution(executionId) {
    const details = document.getElementById("playbookExecutionDetails");
    details.textContent = `Loading execution #${executionId}...`;

    try {
        const res = await fetch(`/api/playbook-executions/${executionId}`);
        const data = await res.json();

        if (!res.ok || data.status !== "success") {
            throw new Error(data.message || "Unable to load execution.");
        }

        const execution = data.execution;
        const steps = (execution.step_results || []).map((step, index) => `
            <div class="playbook-execution-step">
                <div><strong>${index + 1}. ${escapeHtml(step.name || step.step_id)}</strong> ${playbookStatusBadge(step.status)}</div>
                <div style="margin-top: 5px; color: var(--text-muted);">${escapeHtml(step.message || "")}</div>
                <div style="margin-top: 4px; font-size: 11px; color: var(--text-muted);">${playbookFormatDate(step.timestamp)}</div>
            </div>
        `).join("");

        details.innerHTML = `
            <div><strong>Execution #${escapeHtml(execution.id)}</strong> — ${escapeHtml(execution.playbook_name || "")}</div>
            <div style="margin-top: 8px;">Incident #${escapeHtml(execution.incident_id)}: ${escapeHtml(execution.incident_title || "")}</div>
            <div style="margin-top: 8px;">Status ${playbookStatusBadge(execution.status)} Mode ${playbookStatusBadge(execution.execution_mode)} Approval ${playbookStatusBadge(execution.approval_status)} Containment ${playbookStatusBadge(execution.containment_status)}</div>
            <div style="margin-top: 8px;"><strong>Risk / severity:</strong> ${escapeHtml(execution.risk_score)}/100 — ${escapeHtml(execution.severity)}</div>
            <div style="margin-top: 8px;"><strong>Output:</strong><pre style="white-space: pre-wrap; margin-top: 5px; color: var(--text-muted);">${escapeHtml(execution.output_log || "No output recorded.")}</pre></div>
            <div style="margin-top: 12px;"><strong>Workflow step results</strong></div>
            ${steps || '<div style="margin-top: 8px; color: var(--text-muted);">No step results are available yet.</div>'}
        `;
    } catch (error) {
        details.textContent = error.message;
    }
}

async function refreshPlaybookPanel() {
    await Promise.all([
        fetchPlaybooks(),
        fetchPlaybookIncidents(),
        fetchPlaybookExecutions(),
    ]);
}
