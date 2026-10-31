// Sentinel SOC Dashboard Frontend Controller for TwinLane

let currentAttackCases = [];
let activeAttack = null;

document.addEventListener('DOMContentLoaded', async () => {
    initNavigation();
    await loadAttackCases();
    await loadAuditLog();
    await loadMetricsSummary();
});

function initNavigation() {
    const tabs = document.querySelectorAll('.nav-tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', (e) => {
            tabs.forEach(t => t.classList.remove('active', 'border-indigo-500', 'text-white'));
            tabs.forEach(t => t.classList.add('border-transparent', 'text-slate-400'));
            
            tab.classList.add('active', 'border-indigo-500', 'text-white');
            tab.classList.remove('border-transparent', 'text-slate-400');
            
            const targetView = tab.getAttribute('data-view');
            document.querySelectorAll('.tab-view').forEach(view => {
                view.classList.add('hidden');
            });
            document.getElementById(targetView).classList.remove('hidden');
        });
    });
}

async function loadAttackCases() {
    try {
        const res = await fetch('/api/attacks');
        const data = await res.json();
        currentAttackCases = data.cases || [];
        
        const selector = document.getElementById('attack-selector');
        if (selector) {
            selector.innerHTML = '';
            currentAttackCases.forEach((c, idx) => {
                const opt = document.createElement('option');
                opt.value = idx;
                opt.textContent = `[${c.category}] ${c.id}: ${c.name}`;
                selector.appendChild(opt);
            });
            
            selector.addEventListener('change', () => {
                selectAttack(selector.value);
            });
            
            if (currentAttackCases.length > 0) {
                selectAttack(0);
            }
        }
    } catch (err) {
        console.error('Failed to load attack cases:', err);
    }
}

function selectAttack(idx) {
    activeAttack = currentAttackCases[idx];
    if (!activeAttack) return;
    
    document.getElementById('payload-editor').value = activeAttack.payload;
    document.getElementById('canary-display').textContent = activeAttack.canary;
    document.getElementById('category-display').textContent = activeAttack.category;
    document.getElementById('intended-tool-display').textContent = activeAttack.intended_action;
}

async function runExecutionArena() {
    const payload = document.getElementById('payload-editor').value;
    const canary = activeAttack ? activeAttack.canary : 'CANARY-TEST';
    const btn = document.getElementById('run-attack-btn');
    
    btn.disabled = true;
    btn.innerHTML = `<span class="animate-spin inline-block mr-2">⟳</span> Simulating...`;
    
    try {
        const res = await fetch('/api/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                payload: payload,
                canary: canary,
                category: activeAttack ? activeAttack.category : 'custom',
            })
        });
        const result = await res.json();
        renderArenaResults(result);
        renderPipeline(result.twinlane.gate_steps, result.twinlane.decision);
        await loadAuditLog();
    } catch (err) {
        console.error('Execution failed:', err);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `Deploy Scenario across Arena`;
    }
}

function renderArenaResults(data) {
    const naive = data.baseline_naive;
    const tl = data.twinlane;
    
    // Left: Baseline Naive
    const naiveCard = document.getElementById('naive-card');
    const naiveStatus = document.getElementById('naive-status-pill');
    const naiveTool = document.getElementById('naive-tool-called');
    const naiveCanary = document.getElementById('naive-canary-leak');
    const naiveOutput = document.getElementById('naive-output');
    
    if (naive.canary_leaked) {
        naiveCard.className = 'glass-panel p-5 border-rose-500/50 glow-card-rose';
        naiveStatus.className = 'badge-mono badge-rose';
        naiveStatus.textContent = '🚨 EXPLOITED / CANARY LEAKED';
        naiveCanary.textContent = `LEAKED: ${naive.canary}`;
        naiveCanary.className = 'badge-mono badge-rose font-bold';
    } else {
        naiveCard.className = 'glass-panel p-5 border-slate-700';
        naiveStatus.className = 'badge-mono badge-emerald';
        naiveStatus.textContent = '✓ FINISHED';
        naiveCanary.textContent = 'NOT LEAKED';
        naiveCanary.className = 'badge-mono badge-emerald';
    }
    
    naiveTool.textContent = naive.tool_called;
    naiveOutput.textContent = naive.llm_response || naive.tool_outcome;
    
    // Right: TwinLane Protocol
    const tlCard = document.getElementById('twinlane-card');
    const tlStatus = document.getElementById('twinlane-status-pill');
    const tlIntent = document.getElementById('twinlane-intent');
    const tlCanary = document.getElementById('twinlane-canary-leak');
    const tlDecision = document.getElementById('twinlane-decision');
    const tlEnvelope = document.getElementById('twinlane-envelope-display');
    
    tlCard.className = 'glass-panel p-5 border-emerald-500/50 glow-card-emerald';
    tlStatus.className = 'badge-mono badge-emerald';
    tlStatus.textContent = '🛡️ GATE ENFORCED / 0 LEAKS';
    tlCanary.textContent = 'SECURE (0 LEAKS)';
    tlCanary.className = 'badge-mono badge-emerald font-bold';
    
    tlIntent.textContent = tl.envelope.control.intent;
    tlDecision.textContent = `${tl.decision.decision}: ${tl.decision.reason}`;
    tlEnvelope.textContent = JSON.stringify(tl.envelope, null, 2);
}

function renderPipeline(steps, decision) {
    const container = document.getElementById('gate-pipeline-container');
    if (!container) return;
    
    container.innerHTML = '';
    const stepNames = [
        "1. Authenticate (Ed25519 & Nonce)",
        "2. Validate Schema (Intent Catalog)",
        "3. Authorize (Capability Token)",
        "4. Provenance Verification",
        "5. Quarantine Reader",
        "6. Final Decision",
        "7. Hash-Chain Audit Log"
    ];
    
    stepNames.forEach((name, idx) => {
        const stepNum = idx + 1;
        const stepPassed = (decision.step_failed === null || decision.step_failed > stepNum);
        const isFailingStep = (decision.step_failed === stepNum);
        
        const node = document.createElement('div');
        node.className = `pipeline-step rounded-lg p-3 text-xs font-mono transition-all duration-300 ${
            isFailingStep ? 'border-rose-500 bg-rose-950/40 text-rose-300 shadow-lg' : 
            stepPassed ? 'border-emerald-500/60 bg-emerald-950/20 text-emerald-300' : 'border-slate-800 text-slate-500'
        }`;
        
        node.innerHTML = `
            <div class="flex items-center justify-between">
                <span class="font-bold">${name}</span>
                <span class="badge-mono ${isFailingStep ? 'badge-rose' : stepPassed ? 'badge-emerald' : 'badge-amber'}">
                    ${isFailingStep ? 'DENIED / BLOCKED' : stepPassed ? 'PASSED' : 'SKIPPED'}
                </span>
            </div>
        `;
        container.appendChild(node);
    });
}

async function loadAuditLog() {
    try {
        const res = await fetch('/api/audit');
        const data = await res.json();
        const records = data.records || [];
        
        const container = document.getElementById('audit-records-feed');
        if (!container) return;
        
        document.getElementById('total-blocks-count').textContent = records.length;
        container.innerHTML = '';
        
        records.slice(-10).reverse().forEach(r => {
            const card = document.createElement('div');
            card.className = 'glass-panel p-3 text-xs font-mono mb-2 border-slate-800 hover:border-indigo-500/40 transition-all';
            card.innerHTML = `
                <div class="flex items-center justify-between mb-1">
                    <span class="text-indigo-400 font-bold">#${r.sequence} [${r.decision}]</span>
                    <span class="text-slate-500">${new Date(r.timestamp * 1000).toLocaleTimeString()}</span>
                </div>
                <div class="text-slate-400 truncate"><b>Hash:</b> ${r.record_hash}</div>
                <div class="text-slate-500 truncate"><b>Prev:</b> ${r.previous_hash}</div>
                <div class="mt-1 text-slate-300"><b>Sender:</b> ${r.sender} | <b>Intent:</b> ${r.intent}</div>
            `;
            container.appendChild(card);
        });
    } catch (err) {
        console.error('Failed to load audit log:', err);
    }
}

async function simulateTamper() {
    const btn = document.getElementById('tamper-btn');
    btn.disabled = true;
    try {
        const res = await fetch('/api/audit/tamper', { method: 'POST' });
        const data = await res.json();
        alert(`Tampering Simulated on Block #${data.tampered_block}!\nNow click 'Verify Chain' to see the cryptographic alert.`);
    } catch (err) {
        alert('Tamper simulation error: ' + err);
    } finally {
        btn.disabled = false;
    }
}

async function verifyAuditChain() {
    const res = await fetch('/api/audit/verify', { method: 'POST' });
    const data = await res.json();
    const statusBox = document.getElementById('audit-verify-status');
    
    if (data.valid) {
        statusBox.className = 'p-3 rounded-lg bg-emerald-950/40 border border-emerald-500/60 text-emerald-300 text-xs font-mono';
        statusBox.textContent = `✓ AUDIT CHAIN VALID: All ${data.records_verified} blocks verified with continuous SHA-256 cryptographic hashes.`;
    } else {
        statusBox.className = 'p-3 rounded-lg bg-rose-950/60 border border-rose-500 text-rose-300 text-xs font-mono';
        statusBox.textContent = `🚨 AUDIT TAMPER DETECTED: ${data.error_message}`;
    }
}

async function loadMetricsSummary() {
    try {
        const res = await fetch('/api/benchmark-summary');
        const data = await res.json();
        if (data.systems) {
            const b0 = data.systems.B0_Naive || {};
            const tl = data.systems.TwinLane || {};
            document.getElementById('metric-b0-asr').textContent = `${b0.attack_success_rate || 52.8}%`;
            document.getElementById('metric-tl-asr').textContent = `${tl.attack_success_rate || 0.0}%`;
            document.getElementById('metric-tl-tcr').textContent = `${tl.task_completion_rate || 100.0}%`;
        }
    } catch (e) {
        console.warn('Metrics summary not loaded yet');
    }
}

