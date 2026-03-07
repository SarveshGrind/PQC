const API_BASE = 'http://localhost:3000/api';

// DOM Elements
const loginSection = document.getElementById('login-section');
const dashboardSection = document.getElementById('dashboard-section');
const loginForm = document.getElementById('login-form');
const logoutBtn = document.getElementById('logout-btn');
const analyzeForm = document.getElementById('analyze-form');
const statusCard = document.getElementById('status-card');
const jobStateBadge = document.getElementById('job-state');
const jobMessage = document.getElementById('job-message');
const resultsSummary = document.getElementById('results-summary');
const findingsTableContainer = document.getElementById('findings-table-container');
const findingsBody = document.getElementById('findings-body');
const qrsValue = document.getElementById('qrs-value');

// State
let authToken = localStorage.getItem('pqc_token');

// Initialization
if (authToken) {
    showDashboard();
}

// --- Auth Handling ---
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const errorEl = document.getElementById('login-error');

    try {
        const response = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        if (!response.ok) throw new Error('Invalid credentials');

        const data = await response.json();
        authToken = data.token;
        localStorage.setItem('pqc_token', authToken);
        errorEl.classList.add('hidden');
        showDashboard();
    } catch (err) {
        errorEl.textContent = err.message;
        errorEl.classList.remove('hidden');
    }
});

logoutBtn.addEventListener('click', () => {
    authToken = null;
    localStorage.removeItem('pqc_token');
    showLogin();
});

function showDashboard() {
    loginSection.classList.add('hidden');
    dashboardSection.classList.remove('hidden');
    logoutBtn.classList.remove('hidden');
}

function showLogin() {
    loginSection.classList.remove('hidden');
    dashboardSection.classList.add('hidden');
    logoutBtn.classList.add('hidden');
}

// --- Analysis Handling ---
analyzeForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const repoUrl = document.getElementById('repo-url').value;

    // Reset UI
    resultsSummary.classList.add('hidden');
    findingsTableContainer.classList.add('hidden');
    statusCard.classList.remove('hidden');
    updateStatusBadge('QUEUING');

    try {
        const response = await fetch(`${API_BASE}/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ repoUrl })
        });

        if (response.status === 401 || response.status === 403) {
            showLogin();
            return;
        }

        const data = await response.json();
        if (data.jobId) {
            pollJobStatus(data.jobId);
        } else {
            updateStatusBadge('FAILED', data.error || 'Server error');
        }
    } catch (err) {
        updateStatusBadge('FAILED', err.message);
    }
});

async function pollJobStatus(jobId) {
    let polling = true;

    while (polling) {
        await new Promise(r => setTimeout(r, 2000)); // Poll every 2 seconds

        try {
            const response = await fetch(`${API_BASE}/jobs/${jobId}`, {
                headers: { 'Authorization': `Bearer ${authToken}` }
            });

            if (response.status === 404) continue;

            const job = await response.json();
            updateStatusBadge(job.state);

            if (job.state === 'COMPLETED') {
                polling = false;
                renderResults(job.results);
            } else if (job.state === 'FAILED') {
                polling = false;
                jobMessage.textContent = `Error: ${job.error_message}`;
            }
        } catch (err) {
            console.error('Polling error', err);
        }
    }
}

function updateStatusBadge(state, msg = '') {
    jobStateBadge.textContent = state;
    if (msg) jobMessage.textContent = msg;
    else if (state === 'PENDING') jobMessage.textContent = 'Waiting in queue...';
    else if (state === 'CLONING') jobMessage.textContent = 'Cloning repository...';
    else if (state === 'ANALYZING') jobMessage.textContent = 'Running PQC Analyzer CLI...';
    else if (state === 'COMPLETED') jobMessage.textContent = 'Analysis finished successfully.';
}

function renderResults(results) {
    if (!results) return;

    // Render Summary
    resultsSummary.classList.remove('hidden');
    qrsValue.textContent = results.summary?.qrs.toFixed(2) || '0.00';

    // Render Table
    findingsTableContainer.classList.remove('hidden');
    findingsBody.innerHTML = '';

    const findings = results.findings || [];
    findings.forEach(f => {
        const row = document.createElement('tr');

        // Truncate path for display
        const shortPath = f.filePath.split('/').pop();

        row.innerHTML = `
            <td class="break-col">${shortPath}</td>
            <td>${f.lineNumber}</td>
            <td>${f.algorithm}</td>
            <td>${f.keySize || 'Unknown'}</td>
            <td><span class="badge" style="background-color: #f1f5f9; color: #475569;">${f.exposureLevel}</span></td>
            <td>${f.tainted ? 'Yes' : 'No'}</td>
            <td style="font-weight: 600; color: #2563eb;">${f.riskScore.toFixed(2)}</td>
            <td>${f.usageType || 'UNKNOWN'}</td>
            <td><span class="badge" style="background-color: #ffd700; color: #000; white-space: nowrap;">${f.recommendedReplacement || 'Unknown'}</span></td>
        `;
        findingsBody.appendChild(row);
    });
}
