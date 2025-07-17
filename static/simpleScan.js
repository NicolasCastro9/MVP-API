// --- START OF ENHANCED simpleScan.js (Professional Dashboard UI v2 - Con Disclaimer) ---

const ORIGINAL_DOC_TITLE = document.title;
let loadingInterval;

function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return '';
    return unsafe
         .replace(/&/g, "&")
         .replace(/</g, "<")
         .replace(/>/g, ">")
         .replace(/'/g, "'");
}

function showLoadingProgress(container) {
    const messages = ["Iniciando conexión...", "Preparando escaneo...", "Ejecutando Spider...", "Recopilando alertas...", "Analizando con IA...", "Compilando reporte..."];
    let messageIndex = 0;
    container.innerHTML = `<div class="loading-container"><div class="spinner"></div><p class="loading-text">${messages[messageIndex]}</p></div>`;
    const loadingTextElement = container.querySelector('.loading-text');
    clearInterval(loadingInterval);
    loadingInterval = setInterval(() => {
        messageIndex = (messageIndex + 1) % messages.length;
        loadingTextElement.textContent = messages[messageIndex];
    }, 4000);
}

async function scanURL() {
    const url = document.getElementById("urlInput").value.trim();
    const recommendationsDiv = document.getElementById("recommendations");
    document.title = "Escaneando... - SIMPLE-SCAN";

    const urlPattern = /^(http:\/\/|https:\/\/).+$/;
    if (!urlPattern.test(url)) {
        recommendationsDiv.innerHTML = "<p class='error'>URL no válida. Debe comenzar con 'http://' o 'https://'</p>";
        document.title = ORIGINAL_DOC_TITLE; return;
    }

    const cacheKey = `scan_v3_${url}`;
    const cached = sessionStorage.getItem(cacheKey);
    if (cached) {
        try {
            displayResults(JSON.parse(cached), url);
            document.title = `Resultados para ${url} - SIMPLE-SCAN`; return;
        } catch (e) { sessionStorage.removeItem(cacheKey); }
    }
    
    recommendationsDiv.style.display = "block";
    showLoadingProgress(recommendationsDiv);

    try {
        const response = await fetch("http://127.0.0.1:8001/scan", {
            method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: url })
        });
        
        clearInterval(loadingInterval);

        if (!response.ok) {
            const errorText = await response.text();
            let detail;
            try { detail = JSON.parse(errorText).detail || errorText; } catch (e) { detail = errorText; }
            throw new Error(`Error ${response.status}: ${detail}`);
        }

        const data = await response.json();
        displayResults(data, url);
        sessionStorage.setItem(cacheKey, JSON.stringify(data));
        document.title = `Resultados para ${url} - SIMPLE-SCAN`;
    } catch (error) {
        clearInterval(loadingInterval);
        console.error("Error en la solicitud:", error);
        recommendationsDiv.innerHTML = `<p class='error'>Error en el escaneo: ${error.message || 'Intenta nuevamente.'}</p>`;
        document.title = `Error en Escaneo - SIMPLE-SCAN`;
    }
}

function displayResults(data, url) {
    const findings = data.zap_scan?.findings || [];
    const openAIRecommendations = data.openai_recommendations || [];
    const quickChecks = data.quick_checks || {};
    const recommendationsDiv = document.getElementById("recommendations");

    const severityCounts = { high: 0, medium: 0, low: 0, unknown: 0 };
    findings.forEach(finding => {
        severityCounts[(finding.severity || "unknown").toLowerCase()]++;
    });

    recommendationsDiv.innerHTML = `
        <div class="results-header">
            <h3><i class="fas fa-chart-line"></i> Dashboard de Resultados para: ${escapeHtml(url)}</h3>
        </div>
        <div class="results-grid">
            <div class="stats-container">
                <div class="stat-card high"><div class="icon"><i class="fas fa-bomb"></i></div><span class="stat-number">${severityCounts.high}</span><span class="stat-label">Alto Riesgo</span></div>
                <div class="stat-card medium"><div class="icon"><i class="fas fa-exclamation-triangle"></i></div><span class="stat-number">${severityCounts.medium}</span><span class="stat-label">Riesgo Medio</span></div>
                <div class="stat-card low"><div class="icon"><i class="fas fa-shield-alt"></i></div><span class="stat-number">${severityCounts.low}</span><span class="stat-label">Riesgo Bajo</span></div>
            </div>
            <div class="grid-panel chart-panel">
                <h4><i class="fas fa-pie-chart"></i> Distribución de Severidad</h4>
                <div style="position: relative; height:280px; width:100%; margin:auto;"><canvas id="severityChart"></canvas></div>
            </div>
            <div class="grid-panel summary-panel">
                <h4><i class="fas fa-clipboard-list"></i> ¿Qué significa cada nivel?</h4>
                <ul>
                    <li class="high"><strong>Alto:</strong><div class="description">Riesgo crítico. Podría permitir la toma de control del sistema o fuga de datos sensibles. Requiere atención inmediata.</div></li>
                    <li class="medium"><strong>Medio:</strong><div class="description">Riesgo significativo. Podría permitir el acceso no autorizado a información o la interrupción parcial del servicio.</div></li>
                    <li class="low"><strong>Bajo:</strong><div class="description">Riesgo menor. A menudo son debilidades de configuración o informativas que deben ser corregidas para fortalecer la seguridad.</div></li>
                </ul>
            </div>
            <div class="grid-panel quick-checks-panel">
                <h4><i class="fas fa-tasks"></i> Chequeos Rápidos</h4>
                <div class="quick-checks-container"></div>
            </div>
        </div>
        
        <div class="vulnerabilities-section">
            <h4><i class="fas fa-list-ul"></i> Hallazgos Detallados</h4>
            <div class="filter-controls">
                <button class="filter-btn all active" data-severity="all">Todos (${findings.length})</button>
                <button class="filter-btn high" data-severity="high">Alto (${severityCounts.high})</button>
                <button class="filter-btn medium" data-severity="medium">Medio (${severityCounts.medium})</button>
                <button class="filter-btn low" data-severity="low">Bajo (${severityCounts.low})</button>
            </div>
            <div class="vulnerabilities-container"></div>
        </div>

        <!-- NUEVO: Panel de limitaciones al final -->
        <div class="final-info-panel">
            <h4><i class="fas fa-info-circle"></i> Importante: Limitaciones del Escaneo para ${escapeHtml(url)}</h4>
            <p>
                Este es un escáner automatizado de vulnerabilidades, no una prueba de penetración completa. Los escáneres pueden identificar posibles vulnerabilidades, pero también pueden generar falsos positivos. Los resultados deben ser revisados y validados por un profesional de seguridad. Una prueba de penetración implica una evaluación más profunda y manual, simulando ataques reales para identificar y explotar las debilidades de seguridad.
            </p>
        </div>
    `;

    renderQuickChecks(quickChecks.https_certificate);
    renderChart(severityCounts);
    renderVulnerabilities(findings, openAIRecommendations);
    setupFiltering();
}

function renderQuickChecks(httpsCert = {}){
    const container = document.querySelector(".quick-checks-container");
    let html = '';
    if (Object.keys(httpsCert).length > 0) {
        const usesHttpsClass = httpsCert.uses_https_ ? "https-yes" : "https-no";
        html += `<div class="check-item ${usesHttpsClass}"><strong>Usa HTTPS:</strong> ${httpsCert.uses_https_ ? 'Sí' : 'No'}</div>`;
        if (httpsCert.uses_https_ && httpsCert.certificate_valid) {
             html += `<div class="check-item https-yes"><strong>Certificado Válido</strong></div>`;
             if(httpsCert.certificate_details?.valid_until){
                html += `<ul class="cert-details"><li><strong>Válido hasta:</strong> ${escapeHtml(httpsCert.certificate_details.valid_until)} ${httpsCert.certificate_details.is_expired ? '<span class="expired-text">(EXPIRADO)</span>' : ''}</li></ul>`;
             }
        } else if (httpsCert.error) {
            html += `<div class="check-item https-no"><strong>Error Certificado:</strong> ${escapeHtml(httpsCert.error)}</div>`;
        }
    } else {
        html += "<p>No hay datos de chequeos rápidos.</p>";
    }
    container.innerHTML = html;
}

function renderChart(severityCounts) {
    if (!document.getElementById('severityChart') || typeof Chart === 'undefined') return;
    new Chart(document.getElementById('severityChart').getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['Alto', 'Medio', 'Bajo', 'Desconocido'],
            datasets: [{
                data: [severityCounts.high, severityCounts.medium, severityCounts.low, severityCounts.unknown],
                backgroundColor: [
                    'var(--severity-high)', 'var(--severity-medium)', 'var(--severity-low)', 'var(--severity-info)'
                ].map(color => getComputedStyle(document.documentElement).getPropertyValue(color.match(/--[\w-]+/)[0]).trim()),
                borderColor: getComputedStyle(document.documentElement).getPropertyValue('--bg-dark-2').trim(),
                borderWidth: 4
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false, cutout: '70%',
            plugins: { legend: { display: false } }
        }
    });
}

function renderVulnerabilities(findings, openAIRecommendations) {
    const container = document.querySelector(".vulnerabilities-container");
    container.innerHTML = '';
    
    if (findings.length === 0) {
        container.innerHTML = `<div class="no-vulnerabilities-found" style="text-align:center;padding:2rem;background-color:rgba(0,245,212,0.1);border-radius:8px;border:1px solid var(--severity-low);"><i class="fas fa-check-circle" style="font-size:2rem;color:var(--severity-low);display:block;margin-bottom:1rem;"></i><p>¡Excelente! No se encontraron vulnerabilidades significativas.</p></div>`;
        return;
    }

    const findingMap = new Map();
    findings.forEach((finding, index) => findingMap.set(finding, openAIRecommendations[index]));

    const severityOrder = { "high": 1, "medium": 2, "low": 3, "unknown": 4 };
    [...findings].sort((a, b) => severityOrder[(a.severity||"").toLowerCase()] - severityOrder[(b.severity||"").toLowerCase()])
    .forEach((finding, i) => {
        const reco = findingMap.get(finding) || { resumen_descripcion: finding.description, recomendacion: "N/A" };
        const severity = (finding.severity || "unknown").toLowerCase();
        
        const vulnEl = document.createElement("div");
        vulnEl.className = `vulnerability ${severity}`;
        vulnEl.style.animationDelay = `${i * 0.05}s`;
        vulnEl.dataset.severity = severity;

        vulnEl.innerHTML = `
            <div class="vuln-title">
                <span>${escapeHtml(finding.type)}</span>
                <span class="severity-badge">${escapeHtml(finding.severity)}</span>
            </div>
            <div class="vuln-content">
                <p><strong>Descripción (Análisis IA):</strong> ${escapeHtml(reco.resumen_descripcion)}</p>
                <p><strong>Recomendación (Análisis IA):</strong> <span class="ai-recommendation" id="rec-${i}">Cargando...</span></p>
                <p><strong>URL Afectada:</strong> <small>${escapeHtml(finding.url)}</small></p>
                <p><strong>Evidencia:</strong> <small>${escapeHtml(finding.evidence)}</small></p>
            </div>
        `;
        
        container.appendChild(vulnEl);
        
        vulnEl.querySelector('.vuln-title').addEventListener('click', () => {
            vulnEl.classList.toggle('expanded');
            const recSpan = document.getElementById(`rec-${i}`);
            if (vulnEl.classList.contains('expanded') && recSpan.textContent === 'Cargando...') {
                typeWriterEffect(recSpan, reco.recomendacion || 'No disponible.', null, 10);
            }
        });

        if (severity === 'high' && findings.length < 8) {
             setTimeout(() => vulnEl.querySelector('.vuln-title').click(), 100 + i * 50);
        }
    });
}

function setupFiltering() {
    const filterContainer = document.querySelector('.filter-controls');
    if (!filterContainer) return;
    
    filterContainer.addEventListener('click', (e) => {
        if (e.target.tagName !== 'BUTTON') return;
        const filterValue = e.target.dataset.severity;
        filterContainer.querySelector('.active').classList.remove('active');
        e.target.classList.add('active');
        document.querySelectorAll('.vulnerability').forEach(vuln => {
            vuln.classList.toggle('hidden-by-filter', !(filterValue === 'all' || vuln.dataset.severity === filterValue));
        });
    });
}

function typeWriterEffect(element, text, callback, speed = 10) {
    if (!element || typeof text !== 'string') { if (callback) callback(); return; }
    let i = 0;
    element.textContent = '';
    (function type() {
        if (i < text.length) {
            element.textContent += text.charAt(i++);
            setTimeout(type, speed);
        } else if (callback) callback();
    })();
}
// --- END OF ENHANCED simpleScan.js (Professional Dashboard UI v2 - Con Disclaimer) ---