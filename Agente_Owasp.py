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
            if alert.get('risk') != 'Informational':  # Filtrar vulnerabilidades "Informational"
                finding = {
                    "host": target_url,
                    "url": alert.get("url", "No disponible"),
                    "severity": alert.get('risk', 'Desconocido'),
                    "type": alert.get('alert', 'Sin información'),
                    "description": alert.get('description', 'No disponible'),
                    "remediation": alert.get('solution', 'No disponible'),
                    "evidence": alert.get('evidence', 'No disponible')
                }
                scan_results["findings"].append(finding)

        return scan_results

    except Exception as e:
        print(f"Error durante el escaneo: {e}")
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
        with open("Static/simpleScan.html", "r", encoding="utf-8") as f:
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
    print(f"🔍 Escaneando: {target_url}")

    try:
        # 1. Realizar chequeos rápidos primero
        https_check_results = await check_https_and_certificate(target_url)

        # 2. Ejecutar escaneo ZAP
        zap_results = await scan_api(target_url) # Tu función scan_api existente

        if "findings" in zap_results:
            unique_findings = []
            seen_alerts = set()
            for finding in zap_results["findings"]:
                alert_key = (finding["type"], finding["url"], finding["severity"])
                if alert_key not in seen_alerts:
                    unique_findings.append(finding)
                    seen_alerts.add(alert_key)
            zap_results["findings"] = unique_findings

        # 3. Obtener recomendaciones de OpenAI para los hallazgos de ZAP
        # Solo enviar hallazgos de ZAP a OpenAI si existen
        openai_recommendations = []
        if zap_results.get("findings"):
            recommendation_request = ChatGPTRequest(findings=zap_results["findings"])
            openai_response_obj = await get_recommendations(recommendation_request) # Asumo que get_recommendations devuelve un objeto con una clave "results"
            openai_recommendations = openai_response_obj.get("results", [])

        # 4. Combinar todos los resultados
        final_results = {
            "quick_checks": { # Nueva sección para chequeos rápidos
                "https_certificate": https_check_results
            },
            "zap_scan": { # Sección para resultados de ZAP
                 "meta": zap_results.get("meta", {}), # Incluir meta si existe
                 "findings": zap_results.get("findings", []), # Usar .get para evitar KeyError
            },
            "openai_recommendations": openai_recommendations # Las recomendaciones de OpenAI
        }
        # Si hubo un error en el escaneo ZAP, zap_results podría ser {"error": "..."}
        if "error" in zap_results:
            final_results["zap_scan"]["error"] = zap_results["error"]


        return final_results
    except Exception as e:
        # Captura de excepciones más específicas podría ser útil aquí
        print(f"Error general en el endpoint /scan: {e}")
        raise HTTPException(status_code=500, detail=f"Error en el escaneo: {str(e)}")
    

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
            "Te enviaré los detalles de una vulnerabilidad de seguridad web. "
            "Genera un resumen detallado de la descripción de la vulnerabilidad "  # Modificado: Resumen detallado
            "(campo 'description') que proporcione un contexto completo y explique las implicaciones de la vulnerabilidad. " # Agregado: Instrucción para más detalle
            "Además, genera una recomendación detallada y concisa para solucionarla. "
            "No repitas la descripción en la recomendación. Sé directo y técnico. "
            "Responde en el siguiente formato JSON:\n"
            "{\n"
            '  "resumen_descripcion": "[Aquí va el resumen de la descripción]",\n'
            '  "recomendacion": "[Aquí va la recomendación]"\n'
            "}\n\n"
            f"Vulnerabilidad:\n{formatted_finding}"
        )

        payload = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {
                    "role": "system",
                    "content": "Eres un experto en ciberseguridad que proporciona resúmenes concisos de vulnerabilidades web y recomendaciones para solucionarlas."
                },
                {
                    "role": "user",
                    "content": prompt_content
                }
            ],
            "temperature": 0.5  # Ajusta según sea necesario
        }

        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json"
        }

        print(f"Enviando a OpenAI:\n{json.dumps(payload, indent=2)}")

        try:
            response = requests.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers)
            response.raise_for_status()
            response_json = response.json()
            print(f"Respuesta de OpenAI:\n{json.dumps(response_json, indent=2)}")

            response_content = response_json.get("choices", [{}])[0].get("message", {}).get("content", "{}")
            try:
                result = json.loads(response_content)
                resumen_descripcion = result.get("resumen_descripcion", "No disponible")
                recomendacion = result.get("recomendacion", "No disponible")
            except json.JSONDecodeError:
                print(f"Error al decodificar JSON de OpenAI: {response_content}")
                resumen_descripcion = "No disponible"
                recomendacion = "No disponible"

            all_results.append({"resumen_descripcion": resumen_descripcion.strip(), "recomendacion": recomendacion.strip()})

        except requests.exceptions.RequestException as e:
            print(f"Error de OpenAI: {e}")
            all_results.append({"resumen_descripcion": "No disponible", "recomendacion": "No disponible"})

    return {"results": all_results}  # Devuelve un diccionario con la lista de resultados