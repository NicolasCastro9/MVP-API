from fastapi import FastAPI, HTTPException, Request # Añadir Request
from fastapi.responses import HTMLResponse # Añadir HTMLResponse
from fastapi.staticfiles import StaticFiles # Añadir StaticFiles
from fastapi.templating import Jinja2Templates # Opcional si solo sirves HTML estático, pero útil
from pydantic import BaseModel, HttpUrl
from fastapi.middleware.cors import CORSMiddleware
import asyncio
from datetime import datetime
from zapv2 import ZAPv2
import os
import requests
import json
import socket
from datetime import datetime, timezone
import ssl
from urllib.parse import urlparse
import html


scan_lock = asyncio.Lock()
app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Cambia esto en producción a dominios específicos
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuración de OWASP ZAP
ZAP_PROXY = "http://127.0.0.1:8090"
ZAP_API_KEY = os.getenv("ZAP_API_KEY")  # Variable de entorno para la API Key de ZAP
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")  # Variable de entorno para la API Key de OpenAI

progress_data = {}

zap = ZAPv2(proxies={"http": ZAP_PROXY, "https": ZAP_PROXY}, apikey=ZAP_API_KEY)

class ScanRequest(BaseModel):
    url: HttpUrl  # Validar que sea una URL válida

class ChatGPTRequest(BaseModel):
    findings: list  # Recibe los hallazgos de ZAP


async def scan_api(target_url: str):
    """
    Mapea una URL con el Spider de OWASP ZAP por un máximo de 60 segundos,
    recopila TODAS las alertas pasivas y devuelve una lista de hallazgos únicos,
    con especial atención a los detalles de las librerías vulnerables.
    """
    SPIDER_MAX_DURATION = 60

    try:
        print("[+] Limpiando alertas de sesiones previas...")
        zap.core.delete_all_alerts(apikey=ZAP_API_KEY) # Es buena práctica pasar la key siempre

        print(f"[+] Accediendo al objetivo para el spider: {target_url}")
        zap.urlopen(target_url)
        await asyncio.sleep(2)

        print(f"[+] Iniciando Spider (con un tiempo límite de {SPIDER_MAX_DURATION} segundos)...")
        scan_id = zap.spider.scan(target_url)
        if not scan_id:
            raise Exception("No se pudo iniciar el spider.")

        start_time = asyncio.get_event_loop().time()
        while True:
            await asyncio.sleep(5)
            progress = int(zap.spider.status(scan_id))
            elapsed_time = asyncio.get_event_loop().time() - start_time
            
            print(f"[-] Spider en progreso: {progress}% completado. Tiempo transcurrido: {int(elapsed_time)}s")

            if progress >= 100:
                print("[+] Spider completado antes del tiempo límite.")
                break
            
            if elapsed_time >= SPIDER_MAX_DURATION:
                print(f"[!] Límite de tiempo de {SPIDER_MAX_DURATION}s alcanzado. Deteniendo el spider...")
                zap.spider.stop(scan_id)
                await asyncio.sleep(1)
                break

        print("[+] Proceso de spider finalizado. Recopilando alertas...")
        await asyncio.sleep(5)

        all_alerts = zap.core.alerts()
        print(f"[+] Se encontraron {len(all_alerts)} alertas en total (antes de deduplicar).")

        unique_findings_map = {}
        severity_order = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}

        # --- CAMBIO CLAVE EN LA LÓGICA DE DEDUPLICACIÓN ---
        for alert in all_alerts:
            alert_type = alert.get('alert', 'Sin información')
            if alert.get('risk') == 'Informational':
                continue

            # Para las alertas de librerías vulnerables (pluginId 10109 de retire.js)
            # o cualquier alerta que contenga "vulnerable", creamos una clave única
            # basada en la evidencia para no agruparlas.
            unique_key = alert_type
            if alert.get('pluginId') == '10109' or 'vulnerable' in alert_type.lower():
                # La evidencia suele ser el nombre de la librería y su versión.
                evidence = alert.get('evidence', '')
                unique_key = f"{alert_type}::{evidence}"

            current_severity_str = alert.get('risk', 'Desconocido')
            current_severity_val = severity_order.get(current_severity_str, -1)
            
            # Mantenemos la lógica de priorizar por severidad si la clave ya existe
            if unique_key in unique_findings_map:
                existing_alert = unique_findings_map[unique_key]
                existing_severity_val = severity_order.get(existing_alert.get('risk', 'Desconocido'), -1)
                if current_severity_val > existing_severity_val:
                    unique_findings_map[unique_key] = alert
            else:
                unique_findings_map[unique_key] = alert
        
        unique_alerts = list(unique_findings_map.values())
        print(f"[+] Después de deduplicar y priorizar, quedan {len(unique_alerts)} vulnerabilidades únicas.")

        scan_results = {
            "meta": {
                "scan_date": datetime.utcnow().isoformat(),
                "scanner_version": "OWASP ZAP (Spider + Passive Scan)"
            },
            "findings": []
        }

        # --- CAMBIO CLAVE AL CONSTRUIR LOS RESULTADOS ---
        for alert in unique_alerts:
            # Ahora capturamos los detalles ricos de CADA alerta
            finding = {
                "host": target_url,
                "url": alert.get('url', 'URL no especificada'),
                "evidence": alert.get('evidence', 'No disponible'),
                "severity": alert.get('risk', 'Desconocido'),
                "type": alert.get('alert', 'Sin información'),
                "description": alert.get('description', 'No disponible'),
                "remediation": alert.get('solution', 'No disponible'),
                # El campo 'other' a menudo contiene oro puro para librerías vulnerables
                "details": alert.get('other', 'Sin detalles adicionales.') 
            }
            scan_results["findings"].append(finding)

        return scan_results

    except Exception as e:
        print(f"Error durante el escaneo con spider: {e}")
        return {"error": f"Error en el escaneo: {str(e)}"}


async def check_https_and_certificate(target_url: str):
    """
    Verifica si el sitio usa HTTPS y la validez básica del certificado.
    Devuelve un diccionario con los hallazgos.
    """
    findings = {
        "uses_https_": False,
        "https_redirect": "No verificado", # Podrías intentar acceder a HTTP y ver si redirige
        "certificate_valid": False,
        "certificate_details": {},
        "error": None
    }
    parsed_url = urlparse(target_url)
    hostname = parsed_url.hostname
    port = parsed_url.port if parsed_url.port else 443

    if parsed_url.scheme == "https":
        findings["uses_https_"] = True
        try:
            # Intenta establecer una conexión SSL/TLS
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert() # Obtiene el certificado del peer
                    findings["certificate_valid"] = True # Si llegamos aquí, la conexión fue exitosa y el cert es confiable por el contexto por defecto

                    # Extraer detalles del certificado
                    if cert:
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        subject = dict(x[0] for x in cert.get('subject', []))
                        findings["certificate_details"] = {
                            "issuer_common_name": issuer.get("commonName", "N/A"),
                            "subject_common_name": subject.get("commonName", "N/A"),
                            "valid_from": cert.get("notBefore", "N/A"),
                            "valid_until": cert.get("notAfter", "N/A"),
                            "serial_number": cert.get("serialNumber", "N/A"),
                            # Puedes convertir las fechas notBefore y notAfter a objetos datetime
                            # from ssl import DER_cert_to_PEM_cert
                            # from cryptography import x509
                            # from cryptography.hazmat.backends import default_backend
                            # pem_cert = DER_cert_to_PEM_cert(ssock.getpeercert(True))
                            # loaded_cert = x509.load_pem_x509_certificate(pem_cert.encode(), default_backend())
                            # findings["certificate_details"]["valid_until_datetime"] = loaded_cert.not_valid_after.isoformat()
                        }
                        # Comprobación simple de expiración (el contexto por defecto ya lo hace, pero para mostrar)
                        if "notAfter" in cert:
                            try:
                                expiry_timestamp_utc = ssl.cert_time_to_seconds(cert["notAfter"])
                                expiry_date = datetime.fromtimestamp(expiry_timestamp_utc, timezone.utc)
                                if expiry_date < datetime.now(timezone.utc):
                                    findings["certificate_valid"] = False
                                    findings["certificate_details"]["is_expired"] = True
                                else:
                                    findings["certificate_details"]["is_expired"] = False
                                findings["certificate_details"]["valid_until_datetime_utc"] = expiry_date.isoformat()
                            except ValueError as e:
                                print(f"Error parsing certificate date: {e}")


        except ssl.SSLCertVerificationError as e:
            findings["error"] = f"Error de verificación del certificado SSL: {e.reason if hasattr(e, 'reason') else str(e)}"
            findings["certificate_valid"] = False
            findings["certificate_details"]["error"] = str(e)
        except ssl.SSLError as e:
            findings["error"] = f"Error de SSL: {str(e)}"
            findings["certificate_valid"] = False
            findings["certificate_details"]["error"] = str(e)
        except socket.timeout:
            findings["error"] = "Timeout al conectar para verificar HTTPS/Certificado."
        except socket.gaierror:
            findings["error"] = f"Error de resolución de nombre para {hostname}."
        except ConnectionRefusedError:
            findings["error"] = f"Conexión rechazada al verificar HTTPS/Certificado en {hostname}:{port}."
        except Exception as e:
            findings["error"] = f"Error inesperado al verificar HTTPS/Certificado: {str(e)}"
    elif parsed_url.scheme == "http":
        findings["uses_https_"] = False
        # Opcional: Intentar acceder a la versión HTTPS para ver si hay redirección
        try:
            https_url_attempt = target_url.replace("http://", "https://", 1)
            response = requests.get(https_url_attempt, timeout=5, allow_redirects=False) # No seguir redirecciones inicialmente
            if 300 <= response.status_code < 400 and response.headers.get("Location", "").startswith("https://"):
                findings["https_redirect"] = "Sí, redirige a HTTPS."
            elif response.status_code == 200 and response.url.startswith("https://"): # Accedió directamente a HTTPS
                 findings["https_redirect"] = "Sí, accesible directamente por HTTPS (sin redirección explícita desde HTTP)."
                 # Podrías llamar a check_https_and_certificate recursivamente aquí para la URL HTTPS
            else:
                findings["https_redirect"] = "No, o no redirige a HTTPS."
        except requests.RequestException:
            findings["https_redirect"] = "No se pudo verificar la redirección a HTTPS (posiblemente HTTPS no disponible)."
    else:
        findings["error"] = "Esquema de URL no soportado para chequeo HTTPS (solo http o https)."

    return findings


# --- RUTA PARA SERVIR simpleScan.html EN LA RAÍZ ---
@app.get("/", response_class=HTMLResponse)
async def serve_spa(request: Request):
    # Abre y lee el archivo simpleScan.html
    # Asegúrate de que la ruta al archivo sea correcta según tu estructura de carpetas.
    try:
        with open("static/simpleScan.html", "r", encoding="utf-8") as f:
            html_content = f.read()
        return HTMLResponse(content=html_content, status_code=200)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="simpleScan.html not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error serving HTML: {str(e)}")

class ScanRequest(BaseModel):
    url: HttpUrl

class ChatGPTRequest(BaseModel):
    findings: list

@app.post("/scan")
async def scan(request: ScanRequest):
    target_url = str(request.url)
    print(f"🚦 Petición de escaneo recibida para: {target_url}. Esperando el turno...")

    # --- NUEVO: Usamos el Lock aquí ---
    # El código dentro de este bloque no se ejecutará hasta que el lock esté libre.
    # Si otro escaneo está en curso, esta línea hará que la petición espere aquí.
    async with scan_lock:
        print(f"✅ Turno obtenido. Iniciando escaneo para: {target_url}")
        
        try:
            # Toda la lógica que ya tenías se mantiene igual, pero ahora está protegida.
            https_check_results = await check_https_and_certificate(target_url)
            zap_results = await scan_api(target_url)

            openai_recommendations = []
            if zap_results.get("findings"):
                recommendation_request = ChatGPTRequest(findings=zap_results["findings"])
                openai_response_obj = await get_recommendations(recommendation_request)
                openai_recommendations = openai_response_obj.get("results", [])

            final_results = {
                "quick_checks": {
                    "https_certificate": https_check_results
                },
                "zap_scan": {
                     "meta": zap_results.get("meta", {}),
                     "findings": zap_results.get("findings", []),
                },
                "openai_recommendations": openai_recommendations
            }
            if "error" in zap_results:
                final_results["zap_scan"]["error"] = zap_results["error"]

            print(f"🏁 Escaneo completado para: {target_url}. Liberando el lock.")
            return final_results
        
        except Exception as e:
            print(f"❌ Error durante el escaneo protegido para {target_url}: {e}")
            # Asegurarse de que el error también se maneje dentro del contexto del lock.
            raise HTTPException(status_code=500, detail=f"Error en el escaneo: {str(e)}")

    # Al salir del bloque `async with`, el lock se libera automáticamente, 
    # permitiendo que la siguiente petición en la cola comience.
    

@app.post("/recommendations")
async def get_recommendations(request: ChatGPTRequest):
    """
    Envía los hallazgos de ZAP a OpenAI y devuelve tanto resúmenes de la descripción como recomendaciones.
    """
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="API Key de OpenAI no configurada.")

    all_results = []  # Cambiado a all_results para almacenar ambos: resumen y recomendación
    for finding in request.findings:
        formatted_finding = json.dumps(finding, indent=2, ensure_ascii=False)

        prompt_content = (
            "Eres un analista de ciberseguridad experto. Te proporciono un hallazgo de vulnerabilidad en formato JSON. Tu tarea es analizarlo y devolver un JSON con dos claves:\n\n"
            "1.  **resumen_descripcion**: Crea un resumen técnico claro. **Prioriza la información del campo 'details' y 'evidence'**. El campo 'details' a menudo contiene resúmenes de CVE o el componente específico. El campo 'evidence' te dirá qué librería o componente es. Si 'description' es genérico, ignóralo y céntrate en los otros campos para explicar la vulnerabilidad.\n\n"
            "2.  **recomendacion**: Proporciona una recomendación de solución específica y accionable. **Usa 'evidence' (ej. nombre de librería y versión) y 'details' (que puede sugerir una versión segura) para ser muy preciso**. Por ejemplo, si encuentras 'evidence: jquery-1.12.4.js' y 'details' menciona una vulnerabilidad XSS, tu recomendación debe ser 'Actualizar la librería jQuery a la versión 3.5.0 o superior para mitigar la CVE-XXXX-XXXX encontrada en la URL...'.\n\n"
            "Responde únicamente con el siguiente formato JSON, sin texto introductorio ni explicaciones adicionales:\n"
            "{\n"
            '  "resumen_descripcion": "[Tu resumen técnico basado en details y evidence]",\n'
            '  "recomendacion": "[Tu recomendación específica para actualizar el componente de evidence]"\n'
            "}\n\n"
            f"--- HALLAZGO A ANALIZAR ---\n{formatted_finding}"
        )

        payload = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {
                    "role": "system",
                    "content": "Eres un experto en ciberseguridad que analiza datos de escáneres y proporciona resúmenes técnicos y recomendaciones de solución específicas, respondiendo siempre en formato JSON."
                },
                {
                    "role": "user",
                    "content": prompt_content
                }
            ],
            "temperature": 0.2, # Un poco más determinista para respuestas consistentes
            "response_format": {"type": "json_object"} # ¡NUEVO! Fuerza la salida en JSON (en modelos compatibles)
        }

        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json"
        }
        print("="*50)
        print(f"Enviando a OpenAI:\n{json.dumps(payload, indent=2)}")
        print("="*50)

        try:
            response = requests.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers)
            response.raise_for_status()
            response_json = response.json()

            response_content = response_json.get("choices", [{}])[0].get("message", {}).get("content", "{}")
            try:
                result = json.loads(response_content)
                resumen = result.get("resumen_descripcion", "No se pudo generar un resumen para este hallazgo.")
                reco = result.get("recomendacion", "No se pudo generar una recomendación para este hallazgo.")
                
                all_results.append({"resumen_descripcion": resumen.strip(), "recomendacion": reco.strip()})
            except (json.JSONDecodeError, TypeError):
                print(f"[!] Error: La respuesta de OpenAI no fue un JSON válido para el hallazgo '{finding.get('type')}'. Contenido: {response_content}")
                all_results.append({
                    "resumen_descripcion": f"El análisis por IA falló. Descripción original: {html.escape(finding.get('description', 'N/A'))}",
                    "recomendacion": f"El análisis por IA falló. Solución original: {html.escape(finding.get('solution', 'N/A'))}"
                })

        except requests.exceptions.RequestException as e:
            print(f"[!] Error de conexión con OpenAI: {e}")
            all_results.append({
                "resumen_descripcion": "Error al conectar con el servicio de IA.",
                "recomendacion": "No se pudo obtener la recomendación debido a un error de red."
            })

    return {"results": all_results}  # Devuelve un diccionario con la lista de resultados