// --- START OF ENHANCED simpleScan.js (Corrected and Improved) ---

// Guardar el título original de la página
const ORIGINAL_DOC_TITLE = document.title;

async function scanURL() {
    const url = document.getElementById("urlInput").value.trim();
    const recommendationsDiv = document.getElementById("recommendations");
    document.title = "Escaneando... - SIMPLE-SCAN"; // Cambiar título

    const urlPattern = /^(http:\/\/|https:\/\/).+$/;
    if (!urlPattern.test(url)) {
        recommendationsDiv.innerHTML = "<p class='error'>Por favor, ingresa una URL válida. Debe comenzar con 'http://' o 'https://'</p>";
        recommendationsDiv.style.display = "block";
        document.title = ORIGINAL_DOC_TITLE; // Restaurar título
        return;
    }

    const cacheKey = `scan_v3_${url}`; // Mantener consistencia si cambias la versión de los datos cacheados
    const cached = sessionStorage.getItem(cacheKey);

    if (cached) {
        try {
            const cachedData = JSON.parse(cached);
            if (cachedData && typeof cachedData === 'object') {
                displayResults(cachedData, url);
                document.title = `Resultados para ${url} - SIMPLE-SCAN`; // Título con URL
                return;
            } else {
                sessionStorage.removeItem(cacheKey); // Cache inválida
            }
        } catch (e) {
            console.error("Error al parsear caché:", e);
            sessionStorage.removeItem(cacheKey); // Cache corrupta
        }
    }

    recommendationsDiv.innerHTML = `
        <div class="loading-container">
            <div class="spinner"></div>
            <p class="loading-text">🔍 Escaneando vulnerabilidades... Esto puede tardar, por favor, espera.</p>
        </div>`;
    recommendationsDiv.style.display = "block";

    try {
        const response = await fetch("http://127.0.0.1:8001/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            const errorText = await response.text();
            let detail = errorText;
            try {
                const errorJson = JSON.parse(errorText);
                detail = errorJson.detail || errorText;
            } catch (e) { /* No es JSON, usar el texto tal cual */ }
            throw new Error(`Error en la respuesta del servidor: ${response.status} - ${detail}`);
        }

        const data = await response.json();
        if (data && typeof data === 'object') {
            displayResults(data, url);
            sessionStorage.setItem(cacheKey, JSON.stringify(data));
            document.title = `Resultados para ${url} - SIMPLE-SCAN`; // Título con URL
        } else {
            throw new Error("La respuesta del servidor no tiene la estructura esperada.");
        }

    } catch (error) {
        console.error("Error en la solicitud:", error);
        recommendationsDiv.innerHTML = `<p class='error'>Error en el escaneo: ${error.message || 'Intenta nuevamente.'}</p>`;
        document.title = `Error en Escaneo - SIMPLE-SCAN`; // Título de error
    }
}


async function displayResults(data, url) {
    const zapScanData = data.zap_scan || {};
    let findings = zapScanData.findings || [];
    const openAIRecommendations = data.openai_recommendations || [];
    const quickChecks = data.quick_checks || {};

    const recommendationsDiv = document.getElementById("recommendations");
    recommendationsDiv.innerHTML = `
        <h3><i class="fas fa-search-location"></i> Resultados del Escaneo para ${escapeHtml(url)}:</h3>
        <div class="quick-checks-container"></div>
        <div class="summary-container"></div>
        <div class="vulnerabilities-container"></div>
        <div class="info-container final-info"></div>
    `;

    const quickChecksContainer = document.querySelector(".quick-checks-container");
    const summaryContainer = document.querySelector(".summary-container");
    const vulnerabilitiesContainer = document.querySelector(".vulnerabilities-container");
    const finalMessagesContainer = document.querySelector(".final-info");

    const severityOrder = { "high": 1, "medium": 2, "low": 3, "unknown": 4, "": 5 };

    // --- Mostrar Chequeos Rápidos ---
    let quickChecksHTML = "<h4><i class='fas fa-tasks'></i> Chequeos Rápidos de Configuración</h4>";
    const httpsCert = quickChecks.https_certificate || {};

    if (Object.keys(httpsCert).length > 0) {
        const usesHttpsClass = httpsCert.uses_https_ ? "https-yes" : "https-no";
        quickChecksHTML += `<div class="check-item ${usesHttpsClass}"><strong>Usa HTTPS:</strong> ${httpsCert.uses_https_ ? 'Sí' : 'No'}</div>`;

        if (httpsCert.uses_https_) {
            const certValidClass = httpsCert.certificate_valid ? "cert-ok" : "cert-bad";
            quickChecksHTML += `<div class="check-item ${certValidClass}"><strong>Certificado Válido:</strong> ${httpsCert.certificate_valid ? 'Sí' : `No ${httpsCert.error ? `(${escapeHtml(httpsCert.error)})` : ''}`}</div>`;
            if (httpsCert.certificate_details && httpsCert.certificate_valid) {
                const certDetails = httpsCert.certificate_details;
                quickChecksHTML += `<ul class="cert-details">
                                        <li><strong>Emitido para:</strong> ${escapeHtml(certDetails.subject_common_name) || 'N/A'}</li>
                                        <li><strong>Emitido por:</strong> ${escapeHtml(certDetails.issuer_common_name) || 'N/A'}</li>
                                        <li><strong>Válido hasta:</strong> ${escapeHtml(certDetails.valid_until) || 'N/A'} ${certDetails.is_expired ? '<span class="expired-text">(EXPIRADO)</span>' : ''}</li>
                                    </ul>`;
            }
        } else if (httpsCert.https_redirect && httpsCert.https_redirect !== "No verificado") {
            quickChecksHTML += `<div class="check-item redirect-info"><strong>Redirección a HTTPS desde HTTP:</strong> ${escapeHtml(httpsCert.https_redirect)}</div>`;
        }
        if (httpsCert.error && !httpsCert.certificate_valid && httpsCert.uses_https_) {
            quickChecksHTML += `<div class="check-item error-message"><strong>Error HTTPS/Cert:</strong> ${escapeHtml(httpsCert.error)}</div>`;
        }
    } else {
        quickChecksHTML += "<p class='info'>No se realizaron o no hay resultados para los chequeos rápidos de HTTPS/Certificado.</p>";
    }
    quickChecksContainer.innerHTML = quickChecksHTML;

    const severityCounts = { high: 0, medium: 0, low: 0, unknown: 0 };
    findings.forEach(finding => {
        const severity = (finding.severity || "unknown").toLowerCase();
        if (severityCounts.hasOwnProperty(severity)) {
            severityCounts[severity]++;
        } else {
            severityCounts.unknown++; // Asegurar que todos se cuentan
        }
    });

    let summaryHTML = `<h4><i class="fas fa-shield-alt"></i> Resumen de Vulnerabilidades (OWASP ZAP)</h4>`;
    if (zapScanData.error) {
        summaryHTML += `<p class="error">Error durante el escaneo ZAP: ${escapeHtml(zapScanData.error)}</p>`;
    } else if (findings.length === 0) {
        // Se manejará más abajo con el contenedor de vulnerabilidades
    } else {
        summaryHTML += `<p>Se encontraron las siguientes vulnerabilidades en el escaneo profundo:</p>
                        <ul class="summary-list">
                            <li class="severity-high">
                                <strong>Alto:</strong> ${severityCounts.high}
                                <div class="description">
                                    Representa un riesgo crítico. Podría permitir la ejecución de código arbitrario, la fuga de datos confidenciales o la toma de control del sistema. Requiere atención inmediata.
                                </div>
                            </li>
                            <li class="severity-medium">
                                <strong>Medio:</strong> ${severityCounts.medium}
                                <div class="description">
                                    Implica un riesgo significativo. Podría permitir el acceso no autorizado a datos sensibles o la interrupción parcial del servicio. Debe ser abordado a la brevedad.
                                </div>
                            </li>
                            <li class="severity-low">
                                <strong>Bajo:</strong> ${severityCounts.low}
                                <div class="description">
                                    Representa un riesgo menor. Podría ser explotado en combinación con otras vulnerabilidades o bajo circunstancias específicas. Debe ser corregido en un plazo razonable.
                                </div>
                            </li>`;
        if (severityCounts.unknown > 0) {
            summaryHTML += `<li class="severity-unknown">
                                <strong>Desconocido/Otro:</strong> ${severityCounts.unknown}
                                <div class="description">
                                    Vulnerabilidades con severidad no clasificada o de carácter informativo que se han incluido para su revisión.
                                </div>
                            </li>`;
        }
        summaryHTML += `</ul>`;

        // --- GRÁFICO DE SEVERIDADES (Chart.js) ---
        if (findings.length > 0) { // Solo mostrar si hay hallazgos
            summaryHTML += `<div style="margin-top: 2rem; margin-bottom: 1.5rem;">
                                <h4><i class="fas fa-chart-pie"></i> Distribución de Severidad</h4>
                                <div style="position: relative; height:250px; width:80%; margin:auto;">
                                     <canvas id="severityChart"></canvas>
                                </div>
                           </div>`;
        }
    }

    const securityHeadersFindings = findings.filter(f =>
        f.type && (
            f.type.toLowerCase().includes("header") ||
            f.type.toLowerCase().includes("x-frame-options") ||
            f.type.toLowerCase().includes("content security policy") ||
            f.type.toLowerCase().includes("csp") ||
            f.type.toLowerCase().includes("strict-transport-security") ||
            f.type.toLowerCase().includes("hsts") ||
            f.type.toLowerCase().includes("x-content-type-options") ||
            f.type.toLowerCase().includes("referrer-policy") ||
            f.type.toLowerCase().includes("permissions-policy")
        )
    );

    const findingToRecommendationMap = new Map();
    if (openAIRecommendations.length === (zapScanData.findings || []).length) {
        (zapScanData.findings || []).forEach((originalFinding, index) => {
            findingToRecommendationMap.set(originalFinding, openAIRecommendations[index]);
        });
    }

    if (securityHeadersFindings.length > 0) {
        summaryHTML += `<h4><i class="fas fa-user-shield"></i> Cabeceras de Seguridad</h4><ul class="security-headers-list">`;
        securityHeadersFindings.forEach(hf => {
            const severityClass = `severity-${(hf.severity || "unknown").toLowerCase()}`;
            const correspondingRecommendation = findingToRecommendationMap.get(hf) ||
                                               { resumen_descripcion: hf.description, recomendacion: "No disponible" };
            const aiSummary = correspondingRecommendation.resumen_descripcion || hf.description;

            summaryHTML += `<li class="${severityClass}"><strong>${escapeHtml(hf.type)}:</strong> ${escapeHtml(hf.severity) || "Desconocida"}
                                <div class="description">${escapeHtml(aiSummary)}</div>
                           </li>`;
        });
        summaryHTML += `</ul>`;
    }

    if (findings.length > 0 && !zapScanData.error) {
        summaryHTML += `
            <h4><i class="fas fa-table-list"></i> Tabla de Resumen de Vulnerabilidades</h4>
            <div class="vulnerability-table-container">
                <table class="vulnerability-table">
                    <thead><tr><th>ID</th><th>Nombre</th><th>Severidad</th></tr></thead>
                    <tbody>`;
        const sortedFindingsForTable = [...findings].sort((a, b) => {
            const severityA = (a.severity || "unknown").toLowerCase();
            const severityB = (b.severity || "unknown").toLowerCase();
            return (severityOrder[severityA] || 5) - (severityOrder[severityB] || 5);
        });

        sortedFindingsForTable.forEach((finding, index) => {
            let severityClass = `severity-${(finding.severity || "unknown").toLowerCase()}`;
            let severityIcon = "<i class='fas fa-question-circle'></i>"; // Default
            if (finding.severity) {
                switch(finding.severity.toLowerCase()){
                    case 'high': severityIcon = "<i class='fas fa-exclamation-triangle'></i>"; break;
                    case 'medium': severityIcon = "<i class='fas fa-exclamation-circle'></i>"; break;
                    case 'low': severityIcon = "<i class='fas fa-info-circle'></i>"; break;
                }
            }
            summaryHTML += `
                <tr>
                    <td>${index + 1}</td>
                    <td>${escapeHtml(finding.type) || "Tipo desconocido"}</td>
                    <td class="${severityClass}">${severityIcon} ${escapeHtml(finding.severity) || "Desconocida"}</td>
                </tr>
            `;
        });
        summaryHTML += `</tbody></table></div>`;
    }
    summaryContainer.innerHTML = summaryHTML;

    // Renderizar Chart.js si el canvas existe
    if (document.getElementById('severityChart') && typeof Chart !== 'undefined') {
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Alto', 'Medio', 'Bajo', 'Desconocido/Otro'],
                datasets: [{
                    label: 'Vulnerabilidades',
                    data: [severityCounts.high, severityCounts.medium, severityCounts.low, severityCounts.unknown],
                    backgroundColor: [
                        getComputedStyle(document.documentElement).getPropertyValue('--severity-high').trim(),
                        getComputedStyle(document.documentElement).getPropertyValue('--severity-medium').trim(),
                        getComputedStyle(document.documentElement).getPropertyValue('--severity-low').trim(),
                        getComputedStyle(document.documentElement).getPropertyValue('--severity-unknown').trim()
                    ],
                    borderColor: getComputedStyle(document.documentElement).getPropertyValue('--bg-dark-3').trim(), // Borde para separar segmentos
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: getComputedStyle(document.documentElement).getPropertyValue('--text-color').trim(),
                            font: { size: 13 }
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                let label = context.label || '';
                                if (label) {
                                    label += ': ';
                                }
                                if (context.parsed !== null) {
                                    label += context.parsed;
                                }
                                return label;
                            }
                        }
                    }
                }
            }
        });
    }


    // --- Mostrar Detalles de Vulnerabilidades de ZAP (SORTED) con ACORDEÓN ---
    if (zapScanData.error) {
        // El error ya se muestra en la sección de resumen
        vulnerabilitiesContainer.innerHTML = ""; // Limpiar si se mostró algo antes
    } else if (findings.length === 0) {
        // --- MENSAJE MEJORADO PARA "NO VULNERABILIDADES" ---
        vulnerabilitiesContainer.innerHTML = `
            <div class="no-vulnerabilities-found">
                <i class="fas fa-shield-check"></i>
                <p>¡Felicidades! No se encontraron vulnerabilidades significativas en el escaneo profundo de ZAP.</p>
            </div>`;
    } else {
        vulnerabilitiesContainer.innerHTML = ''; // Limpiar contenedor

        const sortedFindingsForCards = [...findings].sort((a, b) => {
            const severityA = (a.severity || "unknown").toLowerCase();
            const severityB = (b.severity || "unknown").toLowerCase();
            return (severityOrder[severityA] || 5) - (severityOrder[severityB] || 5);
        });

        for (let i = 0; i < sortedFindingsForCards.length; i++) {
            const finding = sortedFindingsForCards[i];
            const recommendationData = findingToRecommendationMap.get(finding) ||
                                       { resumen_descripcion: escapeHtml(finding.description) || "No disponible", recomendacion: "No disponible" };

            const vulnElement = document.createElement("div");
            vulnElement.classList.add("vulnerability");
            const findingSeverityLower = (finding.severity || "unknown").toLowerCase();
            vulnElement.classList.add(findingSeverityLower);
            vulnElement.style.animationDelay = `${i * 0.08}s`; // Un poco más rápido

            const titleElement = document.createElement('h4');
            titleElement.classList.add('vuln-title');
            const titleTextNode = document.createTextNode(escapeHtml(finding.type) || "Tipo Desconocido");
            titleElement.appendChild(titleTextNode);
            vulnElement.appendChild(titleElement);

            const contentElement = document.createElement('div');
            contentElement.classList.add('vuln-content');

            const severityElement = document.createElement('p');
            severityElement.innerHTML = `<strong>Severidad:</strong> <span class="severity-text-${findingSeverityLower}">${escapeHtml(finding.severity) || "Desconocida"}</span>`;
            contentElement.appendChild(severityElement);

            const urlElement = document.createElement('p');
            urlElement.innerHTML = `<strong>URL:</strong> ${escapeHtml(finding.url) || "N/A"}`;
            contentElement.appendChild(urlElement);

            if (finding.evidence && finding.evidence !== "No disponible") {
                const evidenceElement = document.createElement('p');
                // Para 'evidence', es mejor usar <pre><code> si puede tener formato o saltos de línea
                evidenceElement.innerHTML = `<strong>Evidencia:</strong> <pre><code>${escapeHtml(finding.evidence)}</code></pre>`;
                contentElement.appendChild(evidenceElement);
            }

            const descriptionElement = document.createElement('p');
            descriptionElement.innerHTML = `<strong>Descripción :</strong> ${escapeHtml(recommendationData.resumen_descripcion)}`; // Ya es texto
            contentElement.appendChild(descriptionElement);

            const recommendationElement = document.createElement('p');
            recommendationElement.innerHTML = `<strong>Recomendación :</strong> <span class="ai-recommendation" id="recommendation-card-${i}">Cargando recomendación...</span>`;
            contentElement.appendChild(recommendationElement);

            vulnElement.appendChild(contentElement);
            vulnerabilitiesContainer.appendChild(vulnElement);

            // Usar un objeto para rastrear el estado del typewriter por tarjeta
            vulnElement.dataset.typewriterExecuted = "false";

            titleElement.addEventListener('click', async () => {
                vulnElement.classList.toggle('expanded');
                if (vulnElement.classList.contains('expanded') && vulnElement.dataset.typewriterExecuted === "false") {
                    const recommendationSpan = document.getElementById(`recommendation-card-${i}`);
                    if (recommendationSpan) {
                        const recText = recommendationData.recomendacion || 'No disponible.';
                        if (recText.trim() !== '' && recText !== 'No disponible.') {
                            await typeWriterEffect(recommendationSpan, recText, () => {
                                vulnElement.dataset.typewriterExecuted = "true";
                            }, 10); // Velocidad ajustada
                        } else {
                            recommendationSpan.textContent = 'Recomendación no disponible.';
                            vulnElement.dataset.typewriterExecuted = "true";
                        }
                    }
                }
            });

            if (findingSeverityLower === 'high' && findings.length < 7) { // Expandir si es 'high' y hay pocas
                vulnElement.classList.add('expanded');
                const recommendationSpan = document.getElementById(`recommendation-card-${i}`);
                if (recommendationSpan && vulnElement.dataset.typewriterExecuted === "false") {
                    const recText = recommendationData.recomendacion || 'No disponible.';
                    if (recText.trim() !== '' && recText !== 'No disponible.') {
                        // No esperamos aquí para no bloquear el renderizado de otras tarjetas
                        typeWriterEffect(recommendationSpan, recText, () => {
                            vulnElement.dataset.typewriterExecuted = "true";
                        }, 10);
                    } else {
                        recommendationSpan.textContent = 'Recomendación no disponible.';
                        vulnElement.dataset.typewriterExecuted = "true";
                    }
                }
            }
        }
    }

    displayFinalMessages(finalMessagesContainer, url);
}

function displayFinalMessages(container, url) {
    const finalMessagesHTML = `
        <h4><i class="fas fa-info-circle"></i> Importante: Limitaciones del Escaneo para ${escapeHtml(url)}</h4>
        <p>
            Este es un escáner automatizado de vulnerabilidades, no una prueba de penetración completa. Los escáneres pueden identificar posibles vulnerabilidades, pero también pueden generar falsos positivos. Los resultados deben ser revisados y validados por un profesional de seguridad. Una prueba de penetración implica una evaluación más profunda y manual, simulando ataques reales para identificar y explotar las debilidades de seguridad.
        </p>
    `;
    container.innerHTML = finalMessagesHTML;
    // Animación de aparición para este mensaje
    container.style.opacity = "0";
    container.style.transform = "translateY(20px)";
    setTimeout(() => {
        container.style.transition = "opacity 0.5s ease-out, transform 0.5s ease-out";
        container.style.opacity = "1";
        container.style.transform = "translateY(0)";
    }, 100); // Pequeño retraso para que se aplique después del renderizado
}

// Refined typeWriterEffect for plain text, using textContent and preserving newlines
function typeWriterEffect(element, textContent, callback, speed = 10) { // Default speed
    if (!element || typeof textContent !== 'string') {
        if (callback) callback();
        return;
    }
    let i = 0;
    element.style.whiteSpace = 'pre-wrap'; // Preserve newlines and spaces from the text
    element.textContent = ''; // Clear "Cargando..." or previous content

    function type() {
        if (i < textContent.length) {
            element.textContent += textContent.charAt(i);
            i++;
            setTimeout(type, speed);
        } else {
            if (callback) callback();
        }
    }
    type();
}


// CRITICAL: Corrected escapeHtml function
function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return '';
    return unsafe
         .replace(/&/g, "&")
         .replace(/</g, "<")
         .replace(/>/g, ">")
         .replace(/"/g, '"')
         .replace(/'/g, "'");
}

// --- END OF ENHANCED simpleScan.js (Corrected and Improved) ---