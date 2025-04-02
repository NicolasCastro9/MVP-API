async function buscarAPIs() {
    const dominio = document.getElementById("dominio").value.trim();
    if (!validarDominio(dominio)) return;

    const url = "http://127.0.0.1:8000/find-apis/"; // API Finder
    llamarAPI(url, { domain: dominio }, "🔍 APIs encontradas:", "api");
}






async function escanearVulnerabilidades() {
    window.location.href = "zap.html"
}





async function escanearPuertos() {
    const dominio = document.getElementById("dominio").value.trim();
    if (!validarDominio(dominio)) return;

    const url = "http://127.0.0.1:8002/scan-ports/"; // API Nmap Puertos
    llamarAPI(url, { domain: dominio }, "🔍 Puertos Abiertos:", "puertos");
}





function validarDominio(dominio) {
    if (!dominio || dominio.includes("http") || dominio.includes("//")) {
        mostrarError("Por favor, introduce solo el dominio (ejemplo: ejemplo.com).");
        return false;
    }
    return true;
}




async function llamarAPI(url, data, titulo, tipo) {
    document.getElementById("resultados").innerHTML = "<p>Cargando...</p>";

    try {
        const response = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });

        if (!response.ok) throw new Error("Error en la API: " + response.status);

        const result = await response.json();
        mostrarResultados(result, titulo, tipo);
    } catch (error) {
        mostrarError("Error: " + error.message);
    }
}





function mostrarResultados(datos, titulo, tipo) {
    let html = `<h3>${titulo}</h3>`;

    if (tipo === "api" && datos.apis_found) {
        html += "<ul>";
        datos.apis_found.forEach(api => {
            html += `<li><strong>URL:</strong> <a href="${api.url}" target="_blank" rel="noopener noreferrer">${api.url || "No disponible"}</a></li>`;
        });
        html += "</ul>";
    } else if (tipo === "vulnerabilidad" && datos.findings) {
        if (datos.findings.length > 0) {
            html += "<ul>";
            datos.findings.forEach(vuln => {
                html += `<li>
                    <strong>🔗 Host:</strong> ${vuln.host}<br>
                    <strong>⚠️ Severidad:</strong> <span class="${vuln.severity.toLowerCase()}">${vuln.severity}</span><br>
                    <strong>📖 Descripción:</strong> ${vuln.description}<br>
                    <strong>🛠️ Solución:</strong> ${vuln.remediation}
                </li><br>`;
            });
            html += "</ul>";
        } else {
            html += "<p>No se encontraron vulnerabilidades.</p>";
        }
    } else if (tipo === "puertos" && datos.ports_output) {
        // 🛠️ Manejo de escaneo de puertos (procesar la salida de nmap)
        const regex = /(\d+)\/tcp\s+open\s+(\S+)/g;
        let match;
        let puertos = [];

        while ((match = regex.exec(datos.ports_output)) !== null) {
            puertos.push({ puerto: match[1], servicio: match[2] });
        }
        if (puertos.length > 0) {
            html += "<ul>";
            puertos.forEach(p => {
                html += `<li><strong>Puerto:</strong> ${p.puerto} - <strong>Servicio:</strong> ${p.servicio}</li>`;
            });
            html += "</ul>";
        } else {
            html += "<p>No se encontraron puertos abiertos.</p>";
        }
    } else {
        html += "<p>No se encontraron resultados.</p>";
    }

    document.getElementById("resultados").innerHTML = html;
}

async function buscar_Apis_Dorking() {
    const dominio = document.getElementById("dominio").value.trim();
    if (!validarDominio(dominio)) return;

    const url = "http://127.0.0.1:8003/buscar"; // API de Dorking
    llamarAPI(url, { dominio: dominio }, "🔍 APIs encontradas:", "api");
}




function mostrarError(mensaje) {
    document.getElementById("resultados").innerHTML = `<p style="color:red;">${mensaje}</p>`;
}
