import time
import random
import concurrent.futures
from fastapi import FastAPI
from selenium import webdriver
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from webdriver_manager.firefox import GeckoDriverManager
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import stem
import stem.control

app = FastAPI()

# Habilitar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

# Cache para evitar búsquedas repetidas
cache_busquedas = {}

# Dorks para buscar APIs
dorks = [
    "inurl:/api site:{dominio}",
    "inurl:/docs/api site:{dominio}",
    "inurl:/api/v1 OR inurl:/api/v2 site:{dominio}",
    "inurl:/api-docs OR inurl:/api-documentation site:{dominio}",
    "inurl:/api/ OR inurl:/apis/ OR inurl:/v1/ OR inurl:/v2/ site:{dominio}"
]

# Palabras clave para filtrar resultados
palabras_clave = [
    "api", "swagger", "graphql", "openapi",
    "developer", "docs", "sdk", "documentation",
    "api-reference", "endpoints", "api-overview",
    "swagger-ui", "openapi.json", "swagger.json", "api-docs"
]

def nueva_identidad():
    """ Solicita una nueva identidad en Tor para evitar bloqueos. """
    try:
        with stem.control.Controller.from_port(port=9051) as controller:
            controller.authenticate()
            controller.signal(stem.Signal.NEWNYM)
            print("🔄 Nueva identidad de Tor solicitada.")
    except Exception as e:
        print(f"⚠️ No se pudo cambiar de identidad: {e}")

def configurar_navegador():
    """ Configura y retorna una instancia de Selenium con Tor. """
    options = Options()
    options.add_argument("--headless")
    options.set_preference("network.proxy.type", 1)
    options.set_preference("network.proxy.socks", "127.0.0.1")
    options.set_preference("network.proxy.socks_port", 9050)
    options.set_preference("network.proxy.socks_version", 5)
    options.set_preference("network.proxy.socks_remote_dns", True)

    driver = webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()), options=options)
    return driver

def buscar_dork(dork, dominio):
    """ Realiza una búsqueda en DuckDuckGo con Selenium y retorna URLs encontradas. """
    driver = configurar_navegador()
    urls_encontradas = set()

    try:
        query = dork.replace("{dominio}", dominio)
        url = f"https://duckduckgo.com/?q={query}&t=h_&ia=web"
        driver.get(url)
        time.sleep(random.randint(5, 8))

        resultados = driver.find_elements(By.CSS_SELECTOR, "a[href^='http']")
        for enlace in resultados:
            url_extraida = enlace.get_attribute("href")
            if url_extraida and dominio in url_extraida and "duckduckgo.com" not in url_extraida:
                urls_encontradas.add(url_extraida)

    except Exception as e:
        print(f"Error en búsqueda {dork}: {e}")
    finally:
        driver.quit()

    return urls_encontradas

def filtrar_urls(urls):
    """ Filtra URLs basadas en palabras clave relevantes. """
    return [url for url in urls if any(kw in url.lower() for kw in palabras_clave)]

class DominioRequest(BaseModel):
    dominio: str

@app.post("/buscar")
def buscar_apis(request: DominioRequest):
    """ Busca APIs en el dominio de manera paralela. """
    dominio = request.dominio.strip()

    if not dominio:
        return {"error": "Debe proporcionar un dominio válido"}

    if dominio in cache_busquedas:
        return {"cached": True, "apis_found": cache_busquedas[dominio]}

    urls_totales = set()

    # 🔄 Solicitar nueva identidad antes de hacer las búsquedas
    nueva_identidad()

    # 🔹 Ejecutar búsquedas en paralelo con menos hilos
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futuros = [executor.submit(buscar_dork, dork, dominio) for dork in dorks]
        for futuro in concurrent.futures.as_completed(futuros):
            urls_totales.update(futuro.result())

    # 🔹 Filtrar resultados
    urls_filtradas = filtrar_urls(urls_totales)
    resultado_final = [{"url": url} for url in urls_filtradas]

    # Guardar en caché
    cache_busquedas[dominio] = resultado_final

    return {"cached": False, "apis_found": resultado_final}
