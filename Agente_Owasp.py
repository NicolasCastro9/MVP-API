from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
from fastapi.middleware.cors import CORSMiddleware
import asyncio
from datetime import datetime
from zapv2 import ZAPv2
import os
import requests
import json
import html

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Cambia esto en producción
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuración de OWASP ZAP
ZAP_PROXY = "http://127.0.0.1:8090"
ZAP_API_KEY = os.getenv("ZAP_API_KEY")  # Variable de entorno para la API Key de ZAP
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")  # Variable de entorno para la API Key de OpenAI

zap = ZAPv2(proxies={"http": ZAP_PROXY, "https": ZAP_PROXY}, apikey=ZAP_API_KEY)

class ScanRequest(BaseModel):
    url: HttpUrl  # Validar que sea una URL válida

class ChatGPTRequest(BaseModel):
    findings: list  # Recibe los hallazgos de ZAP

async def scan_api(target_url: str):
    """
    Escanea una URL con OWASP ZAP y devuelve los resultados en JSON.
    """
    try:
        print(f"[+] Accediendo al objetivo: {target_url}")
        zap.urlopen(target_url)
        await asyncio.sleep(2)

        print("[+] Iniciando escaneo activo...")
        scan_id = zap.ascan.scan(target_url)

        if not scan_id:
            raise Exception("No se pudo iniciar el escaneo.")

        while int(zap.ascan.status(scan_id)) < 100:
            print(f"[-] Escaneo en progreso: {zap.ascan.status(scan_id)}% completado")
            await asyncio.sleep(5)

        print("[+] Escaneo completado!")

        alerts = zap.core.alerts(baseurl=target_url)

        scan_results = {
            "meta": {
                "scan_date": datetime.utcnow().isoformat(),
                "scanner_version": "OWASP ZAP 2.x"
            },
            "findings": []
        }

        for alert in alerts:
            finding = {
                "host": target_url,
                "url": alert.get("url", "No disponible"),
                "severity": alert.get('risk', 'Desconocido'),
                "type": alert.get('alert', 'Sin información'),
                "description": html.escape(alert.get('description', 'No disponible')),
                "remediation": html.escape(alert.get('solution', 'No disponible')),
                "evidence": html.escape(alert.get('evidence', 'No disponible'))
            }
            scan_results["findings"].append(finding)

        return scan_results

    except Exception as e:
        return {"error": f"Error en el escaneo: {str(e)}"}

@app.post("/scan")
async def scan(request: ScanRequest):
    target_url = str(request.url)
    print(f"🔍 Escaneando: {target_url}")

    try:
        results = await scan_api(target_url)
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en el escaneo: {str(e)}")

@app.post("/recommendations")
async def get_recommendations(request: ChatGPTRequest):
    """
    Envía los hallazgos de ZAP a OpenAI y devuelve recomendaciones.
    """
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="API Key de OpenAI no configurada.")
    
    formatted_findings = json.dumps(request.findings, indent=2, ensure_ascii=False)

    payload = {
        "model": "gpt-3.5-turbo",
        "messages": [
            {
                "role": "system",
                "content": "Eres un analista de ciberseguridad experto en OWASP TOP 10. Analiza las vulnerabilidades y proporciona impacto y soluciones."
            },
            {
            "role": "user",
            "content": (
                "Te enviaré una lista de hallazgos de seguridad identificados en un escaneo web. "
                "Para cada hallazgo, genera una recomendación personalizada en español que incluya: "
                "**el nombre de la vulnerabilidad**, **la severidad**, **la descripcion de la vulnerabilidad**, **la URL afectada**, **la evidencia (si la evidencia es un script, eliminar el tag <script>)**, "
                "y una **recomendación concreta para solucionarlo**. No repitas la descripción del hallazgo, solo genera la recomendación completa "
                "como si fuera escrita por un experto. Usa Markdown si es necesario para resaltar elementos importantes.\n\n"
                f"Hallazgos:\n{formatted_findings}"
            )
            }
        ],
        "temperature": 0.7
    }

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }

    response = requests.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers)
    
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="Error en la solicitud a OpenAI")

    # Extraer el contenido correctamente
    response_json = response.json()
    recommendations = response_json.get("choices", [{}])[0].get("message", {}).get("content", "No se generaron recomendaciones.")

    return {"recommendations": recommendations}

