async function scanURL() {
    const url = document.getElementById("urlInput").value;
    const recommendationsDiv = document.getElementById("recommendations");

    if (!url) {
        alert("Por favor, ingresa una URL.");
        return;
    }

    // Mostrar mensaje de carga
    recommendationsDiv.innerHTML = "<p class='loading'>🔍 Escaneando... Por favor, espera.</p>";
    recommendationsDiv.style.display = "block";

    try {
        // Enviar solicitud al backend
        const response = await fetch("http://127.0.0.1:8000/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        // Enviar resultados a ChatGPT para recomendaciones
        getChatGPTRecommendations(data);
        
    } catch (error) {
        console.error("Error en la solicitud:", error);
        recommendationsDiv.innerHTML = "<p class='error'>❌ Error en el escaneo. Intenta nuevamente.</p>";
    }
}




async function getChatGPTRecommendations(data) {
    const recommendationsDiv = document.getElementById("recommendations");
    recommendationsDiv.innerHTML = "<p class='loading'>🤖 Generando recomendaciones personalizadas...</p>";

    try {
        const chatGPTResponse = await fetch("https://api.openai.com/v1/chat/completions", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer"  // Reemplaza con tu clave de API
            },
            body: JSON.stringify({
                model: "gpt-3.5-turbo", 
                messages: [
                    {
                        role: "system",
                        content: "Eres un analista de ciberseguridad y experto en pentesting basado en metodologías como OWASP TOP 10. Analiza las siguientes vulnerabilidades y entrega por cada una: la vulnerabilidad, la descripción, el impacto (bajo, medio, alto) y la solución."
                    },
                    {
                        role: "user",
                        content: `Aquí están los hallazgos de seguridad:\n\n${JSON.stringify(data, null, 2)}\n\nPor favor, analiza cada vulnerabilidad y formatea la salida para que sea clara y organizada con títulos y viñetas.`
                    }
                ],
                temperature: 0.7
            })
        });

        const chatGPTData = await chatGPTResponse.json();
        let recommendationText = chatGPTData.choices[0].message.content;


        // Aplicar colores según impacto detectado
        recommendationText = recommendationText
            .replace(/\*\*Impacto:\*\* Bajo/g, "<span class='impact-low'><strong>Impacto:</strong> Bajo</span>")
            .replace(/\*\*Impacto:\*\* Medio/g, "<span class='impact-medium'><strong>Impacto:</strong> Medio</span>")
            .replace(/\*\*Impacto:\*\* Alto/g, "<span class='impact-high'><strong>Impacto:</strong> Alto</span>")
            .replace(/\*\*Impacto:\*\* Informativo/g, "<span class='impact-informational'><strong>Impacto:</strong> Informational</span>");

        // Corrige los encabezados y aplica estilos con listas
        recommendationText = recommendationText
            .replace(/### (.*?)\n/g, "<h4>$1</h4>")  // Convierte títulos a <h4>
            .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>") // Negritas
            .replace(/\n- /g, "<li>")  // Convierte listas en <ul>
            .replace(/\n/g, "</li>")   // Cierra cada ítem
            .replace(/<\/li>(?!<li>)/g, "</li></ul>"); // Asegurar cierre correcto de <ul>

            recommendationsDiv.innerHTML = `<h3>🔍 Recomendaciones:</h3><div class="recommendation-container"></div>`;
            const container = document.querySelector(".recommendation-container");
            typeWriterEffect(container, recommendationText);
        

    } catch (error) {
        console.error("Error en ChatGPT:", error);
        recommendationsDiv.innerHTML = "<p class='error'>❌ No se pudieron generar recomendaciones.</p>";
    }
}





function displayResults(data) {
    const resultsDiv = document.getElementById("results");
    resultsDiv.innerHTML = "";

    if (!data.findings || data.findings.length === 0) {
        resultsDiv.innerHTML = "<p>No se encontraron vulnerabilidades.</p>";
    } else {
        data.findings.forEach(finding => {
            const vulnDiv = document.createElement("div");

            // Normaliza la severidad a minúsculas para evitar errores
            let severity = finding.severity.toLowerCase();
            if (severity === "informational") severity = "info";

            vulnDiv.classList.add("vulnerability", `severity-${severity}`);
            vulnDiv.innerHTML = `
                <h3>${finding.type} (${finding.severity})</h3>
                <p><strong>Host:</strong> <a href="${finding.host}" target="_blank">${finding.host}</a></p>
                <p><strong>Descripción:</strong> ${finding.description}</p>
                <p><strong>Solución:</strong> ${finding.remediation}</p>
            `;


            resultsDiv.appendChild(vulnDiv);
        });
    }

    resultsDiv.style.display = "block"; // Muestra los resultados
}




function typeWriterEffect(element, htmlContent, speed = 5) {
    element.innerHTML = "";  
    let i = 0;

    function type() {
        if (i < htmlContent.length) {
            element.innerHTML = htmlContent.substring(0, i + 1);
            i++;
            setTimeout(type, speed);
        } else {
            element.innerHTML = htmlContent; // Asegurar que quede completo
        }
    }

    type();
}

// 🚀 Manejo del caché
function getCachedResults(query) {
    const cachedData = sessionStorage.getItem(`cache_${query}`);
    console.log(`🔍 Buscando en caché: ${query} →`, cachedData);
    return cachedData ? JSON.parse(cachedData) : null;
}



function saveToCache(query, data) {
    sessionStorage.setItem(`cache_${query}`, JSON.stringify(data));
}




// 🔎 Función para mostrar resultados
function showResults(query, resultContainer) {
    console.log(`🔍 Buscando en caché: ${query}`);
    const cachedData = getCachedResults(query);

    if (cachedData) {
        console.log("📌 Mostrando desde caché");
        resultContainer.innerHTML = cachedData;
    } else {
        console.log("⏳ Generando nuevo resultado");
        const generatedHTML = `<h3>🔍 Resultado para: ${query}</h3><p>Datos generados dinámicamente...</p>`;
        
        resultContainer.innerHTML = generatedHTML;
        saveToCache(query, generatedHTML);
    }
}






// 🖱️ Evento de búsqueda
document.getElementById("searchBtn").addEventListener("click", function () {
    const query = document.getElementById("searchInput").value.trim();
    if (query) {
        showResults(query, document.getElementById("resultsContainer"));
    }
});



