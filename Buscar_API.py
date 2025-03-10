import time
import random
from fastapi import FastAPI
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

# Habilitar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

# Base de datos en memoria (Diccionario)
cache_busquedas = {}

# Lista de Google Dorks
dorks = [
    "inurl:api OR inurl:swagger OR inurl:graphql OR inurl:openapi",
    "inurl:developer/api OR inurl:docs/api OR inurl:sdk OR inurl:api/documentation",
    "inurl:api-reference OR inurl:endpoints OR inurl:api-overview",
    "filetype:json api OR filetype:yaml api OR filetype:xml api",
    "filetype:pdf API Reference OR filetype:md API OR intitle:API Documentation",
    "inurl:swagger-ui OR inurl:openapi.json OR inurl:swagger.json"
]


def configurar_navegador():
    """Configura y retorna una instancia del navegador Selenium."""
    options = Options()
    # options.add_argument("--headless")  # Ejecutar en modo sin interfaz gráfica
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)

    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
    return driver


class DominioRequest(BaseModel):
    dominio: str


@app.post("/buscar")
def buscar_apis(request: DominioRequest):
    """
    Endpoint para buscar APIs en un dominio con Google Dorks.

    Si el dominio ya fue buscado previamente, se devuelve la búsqueda almacenada en caché.
    """
    dominio = request.dominio.strip()

    if not dominio:
        return {"error": "Debe proporcionar un dominio válido"}

    # Si el dominio ya fue buscado antes, devolver los datos almacenados
    if dominio in cache_busquedas:
        return {"cached": True, "apis_found": cache_busquedas[dominio]}

    driver = configurar_navegador()
    urls_encontradas = set()

    try:
        for dork in dorks:
            query = f"site:{dominio} {dork}"
            url = f"https://www.google.com/search?q={query}"

            driver.get(url)
            time.sleep(random.randint(5, 8))  # Espera aleatoria para evitar bloqueos

            # Buscar enlaces en los resultados de Google
            resultados = driver.find_elements(By.CSS_SELECTOR, "div.tF2Cxc a")
            if not resultados:
                resultados = driver.find_elements(By.CSS_SELECTOR, "a[href^='http']")

            for resultado in resultados:
                url_encontrada = resultado.get_attribute("href")
                if url_encontrada and dominio in url_encontrada and "google.com" not in url_encontrada:
                    urls_encontradas.add(url_encontrada)

            time.sleep(random.randint(5, 8))  # Espera entre consultas

    except Exception as e:
        return {"error": f"Ocurrió un error: {str(e)}"}

    finally:
        driver.quit()  # Cerrar el navegador

    # Convertir a lista de diccionarios
    resultado_final = [{"url": url} for url in urls_encontradas]

    # Guardar en caché
    cache_busquedas[dominio] = resultado_final

    return {"cached": False, "apis_found": resultado_final}
