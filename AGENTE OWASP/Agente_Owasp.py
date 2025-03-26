from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
from fastapi.middleware.cors import CORSMiddleware
import asyncio
from datetime import datetime
from zapv2 import ZAPv2
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Cambia esto a los dominios permitidos en producción
    allow_credentials=True,
    allow_methods=["*"],  # Permitir todos los métodos (GET, POST, etc.)
    allow_headers=["*"],  # Permitir todos los headers
)

# Configuración de OWASP ZAP
ZAP_PROXY = "http://127.0.0.1:8090"  # Asegúrate de que ZAP está corriendo en este puerto
API_KEY = os.getenv("ZAP_API_KEY") # Si usas una API Key en ZAP, agrégala aquí

# Instancia de ZAP
zap = ZAPv2(proxies={"http": ZAP_PROXY, "https": ZAP_PROXY}, apikey=API_KEY)

class ScanRequest(BaseModel):
    url: HttpUrl  # Validar que sea una URL válida

async def scan_api(target_url: str):
    """
    Escanea una URL con OWASP ZAP y devuelve los resultados en JSON.
    """
    try:
        print(f"[+] Accediendo al objetivo: {target_url}")
        zap.urlopen(target_url)
        await asyncio.sleep(2)  # Esperar a que se cargue en ZAP

        print("[+] Iniciando escaneo activo...")
        scan_id = zap.ascan.scan(target_url)

        if not scan_id:
            raise Exception("No se pudo iniciar el escaneo.")

        while int(zap.ascan.status(scan_id)) < 100:
            print(f"[-] Escaneo en progreso: {zap.ascan.status(scan_id)}% completado")
            await asyncio.sleep(5)

        print("[+] Escaneo completado!")

        # Obtener alertas encontradas
        alerts = zap.core.alerts(baseurl=target_url)

        # Formatear los resultados
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
                "severity": alert.get('risk', 'Desconocido'),
                "type": alert.get('alert', 'Sin información'),
                "description": alert.get('description', 'No disponible'),
                "remediation": alert.get('solution', 'No disponible'),
                "evidence": alert.get('evidence', 'No disponible')
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