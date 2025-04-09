async function scanURL() {
    const url = document.getElementById("urlInput").value.trim();
    const recommendationsDiv = document.getElementById("recommendations");

    if (!url) {
        alert("Por favor, ingresa una URL.");
        return;
    }

    // Verificar si ya está en caché
    const cached = localStorage.getItem(`scan_${url}`);
    if (cached) {
        const cachedData = JSON.parse(cached);
        console.log("✅ Datos obtenidos de caché:", cachedData);
        displayRecommendations(cachedData.recommendations, cachedData.is_wordpress);
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
        console.log("📦 Data recibida del escaneo:", data);

        const isWordPress = data.meta?.is_wordpress === true;

        // Mostrar mensaje WordPress antes de recomendaciones
        const wpMessage = isWordPress
            ? `<p class="wp-detected">🟡 Este sitio utiliza <strong>WordPress</strong>.</p>`
            : `<p class="wp-not-detected">✅ Este sitio <strong>no</strong> parece usar WordPress.</p>`;
        recommendationsDiv.innerHTML = wpMessage;

        // Enviar a recomendaciones
        const recommendations = await sendToBackendForRecommendations(data);

        // Mostrar recomendaciones junto al mensaje WordPress
        displayRecommendations(recommendations, isWordPress);

        // Guardar en caché
        localStorage.setItem(`scan_${url}`, JSON.stringify({
            findings: data.findings,
            recommendations: recommendations,
            is_wordpress: isWordPress
        }));
    } catch (error) {
        console.error("Error en la solicitud:", error);
        recommendationsDiv.innerHTML = "<p class='error'>❌ Error en el escaneo. Intenta nuevamente.</p>";
    }
}







async function sendToBackendForRecommendations(data) {
    const recommendationsDiv = document.getElementById("recommendations");
    recommendationsDiv.innerHTML = "<p class='loading'>🤖 Generando recomendaciones personalizadas...</p>";

    const payload = { findings: data.findings };
    console.log("Payload enviado:", JSON.stringify(payload));

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
        return chatGPTData.recommendations; // Devolver para guardar en caché
    } catch (error) {
        console.error("Error obteniendo recomendaciones:", error);
        recommendationsDiv.innerHTML = "<p class='error'>❌ No se pudieron generar recomendaciones.</p>";
        return null;
    }
}






function displayRecommendations(recommendationText, isWordPress = false) {
    const recommendationsDiv = document.getElementById("recommendations");

    // Mostrar si es WordPress o no
    const wpMessage = isWordPress
        ? `<p class="wp-detected">🟡 Este sitio utiliza <strong>WordPress</strong>.</p>`
        : `<p class="wp-not-detected">✅ Este sitio <strong>no</strong> parece usar WordPress.</p>`;

    recommendationsDiv.innerHTML = `
        ${wpMessage}
        <h3>🔍 Recomendaciones:</h3>
        <div class="recommendation-container"></div>
    `;

    const container = document.querySelector(".recommendation-container");

    if (!recommendationText) {
        container.innerHTML = "<p class='error'>❌ No se recibieron recomendaciones.</p>";
        return;
    }

    const paragraphs = recommendationText
        .split("\n\n")
        .map(p => p.trim())
        .filter(p => p);

    const vulnerabilities = paragraphs.filter(p =>
        !(p.startsWith("Basándome en los hallazgos") || p.startsWith("En resumen"))
    );

    function processNext(index) {
        if (index >= vulnerabilities.length) return;

        const raw = vulnerabilities[index];

        let vuln = raw
            .replace(/### (.*?)\n/g, "<h4 class='vuln-title'>$1</h4>")
            .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
            .replace(/\n- /g, "<ul><li>")
            .replace(/\n/g, "</li><li>")
            .replace(/<\/li><li>$/, "</li></ul>");

        const vulnElement = document.createElement("div");
        vulnElement.classList.add("vulnerability");
        container.appendChild(vulnElement);

        typeWriterEffect(vulnElement, vuln, () => processNext(index + 1));
    }

    processNext(0);
}








function typeWriterEffect(element, htmlContent, callback, speed = 5) {
    let i = 0;
    let tempDiv = document.createElement("div");

    function type() {
        if (i < htmlContent.length) {
            tempDiv.innerHTML = htmlContent.substring(0, i + 1);
            element.innerHTML = tempDiv.innerHTML;
            i++;

            // 🟡 Scroll automático hacia el final
            const scrollContainer = document.getElementById("recommendations");
            scrollContainer.scrollTo({
                top: scrollContainer.scrollHeight,
                behavior: "smooth"
            });
            

            setTimeout(type, speed);
        } else {
            element.innerHTML = htmlContent;
            if (callback) callback();
        }
    }

    type();
}

