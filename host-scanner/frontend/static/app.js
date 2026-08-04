'use strict';

let _pollInterval = null;
let _allFindings = [];

async function startScan() {
  const btn = document.getElementById('scan-btn');
  const statusEl = document.getElementById('scan-status');

  btn.disabled = true;
  btn.textContent = 'Scanning…';
  statusEl.textContent = 'Initializing scan…';
  statusEl.classList.remove('hidden');

  // Hide old results
  ['progress-section', 'summary-section', 'scanners-section', 'findings-section']
    .forEach(id => document.getElementById(id).classList.add('hidden'));

  const res = await fetch('/api/scan/start', { method: 'POST' });
  if (!res.ok) {
    const err = await res.json();
    statusEl.textContent = 'Error: ' + (err.error || 'Unknown error');
    btn.disabled = false;
    btn.textContent = 'Run Full Scan';
    return;
  }

  document.getElementById('progress-section').classList.remove('hidden');
  _pollInterval = setInterval(pollStatus, 1500);
}

async function pollStatus() {
  try {
    const res = await fetch('/api/scan/status');
    const data = await res.json();

    updateProgress(data.progress);

    const statusEl = document.getElementById('scan-status');
    if (data.error) {
      statusEl.textContent = 'Error: ' + data.error;
    } else if (data.running) {
      const done = Object.values(data.progress).filter(s => s === 'done' || s === 'analyzed').length;
      const total = Object.keys(data.progress).length;
      statusEl.textContent = `Running… ${done}/${total} modules complete`;
    } else {
      statusEl.textContent = 'Scan complete. Loading results…';
    }

    if (!data.running && data.has_results) {
      clearInterval(_pollInterval);
      await loadResults(data.has_report);
      document.getElementById('scan-btn').disabled = false;
      document.getElementById('scan-btn').textContent = 'Run Full Scan';
    }
  } catch (e) {
    console.error('Poll error', e);
  }
}

function updateProgress(progress) {
  const grid = document.getElementById('progress-grid');
  const SCANNERS = ['network','system','software','users','processes','filesystem','startup','hardware'];

  grid.innerHTML = SCANNERS.map(name => {
    const status = progress[name] || 'pending';
    return `
      <div class="progress-item">
        <div class="progress-dot ${status}"></div>
        <span>${name}</span>
        <span style="color:var(--muted);font-size:0.75rem;margin-left:auto">${statusLabel(status)}</span>
      </div>`;
  }).join('');
}

function statusLabel(s) {
  return { pending:'pending', running:'scanning', done:'scanned',
           analyzing:'AI…', analyzed:'analyzed', error:'error',
           analysis_error:'AI err' }[s] || s;
}

async function loadResults(hasReport) {
  const res = await fetch('/api/results');
  if (!res.ok) return;
  const data = await res.json();

  renderExecutive(data.executive, hasReport);
  renderScanners(data.analyses);
  renderFindings(data.analyses);

  ['summary-section', 'scanners-section', 'findings-section']
    .forEach(id => document.getElementById(id).classList.remove('hidden'));
}

function renderExecutive(exec, hasReport) {
  const grade = exec.grade || '?';
  const score = exec.overall_score || 0;

  const badge = document.getElementById('grade-badge');
  badge.textContent = grade;
  badge.className = 'grade-badge grade-' + grade;

  document.getElementById('score-text').textContent = score + '/100';
  document.getElementById('headline').textContent = exec.headline || '';

  // Severity pills (will be filled after renderFindings)
  document.getElementById('severity-counts').innerHTML = '';

  const risks = document.getElementById('top-risks');
  risks.innerHTML = (exec.top_risks || []).map(r => `<li>${r}</li>`).join('');

  const wins = document.getElementById('quick-wins');
  wins.innerHTML = (exec.quick_wins || []).map(q => `<li>${q}</li>`).join('');

  if (hasReport) {
    const link = document.getElementById('report-link');
    link.classList.remove('hidden');
  }
}

function renderScanners(analyses) {
  const grid = document.getElementById('scanner-cards');
  grid.innerHTML = Object.entries(analyses).map(([name, a]) => {
    const score = a.score || 0;
    const cls = score >= 75 ? 'score-good' : score >= 50 ? 'score-ok' : 'score-bad';
    const count = (a.findings || []).length;
    return `
      <div class="scanner-card">
        <div class="scanner-name">${name}</div>
        <div class="scanner-score-num ${cls}">${score}</div>
        <div class="scanner-meta">${count} finding(s)</div>
        <div class="scanner-summary">${a.summary || ''}</div>
      </div>`;
  }).join('');
}

function renderFindings(analyses) {
  _allFindings = [];
  for (const [scanner, a] of Object.entries(analyses)) {
    for (const f of (a.findings || [])) {
      _allFindings.push({ ...f, scanner });
    }
  }

  const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  _allFindings.sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5));

  // Update severity counts
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  _allFindings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });
  const pills = Object.entries(counts)
    .filter(([, n]) => n > 0)
    .map(([sev, n]) => `<div class="sev-pill sev-${sev}">${n} ${sev}</div>`)
    .join('');
  document.getElementById('severity-counts').innerHTML = pills;

  filterFindings();
}

function filterFindings() {
  const filter = document.getElementById('severity-filter').value;
  const rows = filter ? _allFindings.filter(f => f.severity === filter) : _allFindings;
  const tbody = document.getElementById('findings-body');
  tbody.innerHTML = rows.map(f => `
    <tr>
      <td style="font-family:monospace;font-size:0.75rem;white-space:nowrap">${f.id || '—'}</td>
      <td><span class="badge sev-${f.severity}">${f.severity}</span></td>
      <td style="text-transform:capitalize;white-space:nowrap">${f.scanner}</td>
      <td>
        <div class="finding-title">${f.title}</div>
        <div class="finding-desc">${f.description || ''}</div>
      </td>
      <td class="finding-rec">${f.recommendation || ''}</td>
    </tr>`).join('');
}
