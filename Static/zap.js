async function scanURL() {
    const url = document.getElementById("urlInput").value;
    const recommendationsDiv = document.getElementById("recommendations");

    if (!url) {
        alert("Por favor, ingresa una URL.");
        return;
    }

    recommendationsDiv.innerHTML = "<p class='loading'>🔍 Escaneando... Por favor, espera.</p>";
    recommendationsDiv.style.display = "block";

    try {
        const response = await fetch("http://127.0.0.1:8001/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error("Error en la respuesta del servidor");
        }
        
        const data = await response.json();
        console.log("Data recibida del escaneo:", data); // <-- Agregado aquí

        sendToBackendForRecommendations(data);
    } catch (error) {
        console.error("Error en la solicitud:", error);
        recommendationsDiv.innerHTML = "<p class='error'>❌ Error en el escaneo. Intenta nuevamente.</p>";
    }
}

async function sendToBackendForRecommendations(data) {
    const recommendationsDiv = document.getElementById("recommendations");
    recommendationsDiv.innerHTML = "<p class='loading'>🤖 Generando recomendaciones personalizadas...</p>";

    const payload = { findings: data.findings }; // Enviar solo el array de findings

    console.log("Payload enviado:", JSON.stringify(payload)); // Debugging

    try {
        const response = await fetch("http://127.0.0.1:8001/recommendations", { 
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            throw new Error("Error en la respuesta del servidor");
        }
        
        const chatGPTData = await response.json();
        displayRecommendations(chatGPTData.recommendations);
    } catch (error) {
        console.error("Error obteniendo recomendaciones:", error);
        recommendationsDiv.innerHTML = "<p class='error'>❌ No se pudieron generar recomendaciones.</p>";
    }
}


function displayRecommendations(recommendationText) {
    const recommendationsDiv = document.getElementById("recommendations");
    recommendationsDiv.innerHTML = "<h3>🔍 Recomendaciones:</h3><div class='recommendation-container'></div>";
    const container = document.querySelector(".recommendation-container");

    if (!recommendationText) {
        container.innerHTML = "<p class='error'>❌ No se recibieron recomendaciones.</p>";
        return;
    }

    // Separar por párrafos dobles y filtrar introducción y resumen
    const paragraphs = recommendationText.split("\n\n").map(p => p.trim()).filter(p => p);

    // Filtrar la introducción y el resumen
    const vulnerabilities = paragraphs.filter(p => 
        !(p.startsWith("Basándome en los hallazgos") || p.startsWith("En resumen"))
    );

    function processNext(index) {
        if (index >= vulnerabilities.length) return;

        let vuln = vulnerabilities[index]
            .replace(/\*\*Impacto:\*\* Bajo/g, "<span class='impact-low'><strong>Impacto:</strong> Bajo</span>")
            .replace(/\*\*Impacto:\*\* Medio/g, "<span class='impact-medium'><strong>Impacto:</strong> Medio</span>")
            .replace(/\*\*Impacto:\*\* Alto/g, "<span class='impact-high'><strong>Impacto:</strong> Alto</span>")
            .replace(/### (.*?)\n/g, "<h4 class='vuln-title'>$1</h4>") // Resalta el nombre de la vulnerabilidad
            .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
            .replace(/\n- /g, "<ul><li>")
            .replace(/\n/g, "</li><li>")
            .replace(/<\/li><li>$/, "</li></ul>");

        const vulnElement = document.createElement("div");
        vulnElement.classList.add("vulnerability");
        container.appendChild(vulnElement);

        // Aplicar efecto de escritura y pasar a la siguiente vulnerabilidad
        typeWriterEffect(vulnElement, vuln, () => processNext(index + 1));
    }

    processNext(0); // Iniciar con la primera vulnerabilidad
}

function typeWriterEffect(element, htmlContent, callback, speed = 5) {
    let i = 0;
    let tempDiv = document.createElement("div");

    function type() {
        if (i < htmlContent.length) {
            tempDiv.innerHTML = htmlContent.substring(0, i + 1);
            element.innerHTML = tempDiv.innerHTML;
            i++;
            setTimeout(type, speed);
        } else {
            element.innerHTML = htmlContent;
            if (callback) callback(); // Llamar al callback cuando termine
        }
    }

    type();
}
