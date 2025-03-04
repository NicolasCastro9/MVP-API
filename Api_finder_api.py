from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
from fastapi.middleware.cors import CORSMiddleware
import requests
import re
import json
from bs4 import BeautifulSoup
from typing import List, Dict
from urllib.parse import urlparse
from pydantic import field_validator

app = FastAPI(
    title="API Finder",
    description="API para encontrar endpoints de API en dominios web",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Cambia esto a los dominios permitidos en producción
    allow_credentials=True,
    allow_methods=["*"],  # Permitir todos los métodos (GET, POST, etc.)
    allow_headers=["*"],  # Permitir todos los headers
)

class Domain(BaseModel):
    """Modelo para validar el dominio de entrada"""
    domain: str

    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v):
        """Valida que el dominio tenga el formato correcto"""
        if not v or '//' in v or 'http' in v:
            raise ValueError("Por favor, introduce solo el dominio (ejemplo: ejemplo.com)")
        return v

class APIResponse(BaseModel):
    """Modelo para la respuesta con las APIs encontradas"""
    domain: str
    apis_found: List[Dict]
    total_found: int

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

API_PATTERNS = [
    "/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/wp-json/", 
    "/odata/", "/swagger/", "/openapi/", "/docs/", "/api-docs/", 
    "/swagger-ui/", "/graphiql", "/api/v1/", "/api/v2/", "/api/v3/"
]

def find_api_in_html(url: str) -> List[str]:
    """
    Busca endpoints de API en el código HTML de una página web.
    """
    try:
        response = requests.get(url, timeout=5, headers=HEADERS)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script')

        api_endpoints = set()
        api_regex = re.compile(r'https?://[a-zA-Z0-9.-]+/.*?(api|v1|v2|endpoint).*?', re.IGNORECASE)

        for script in scripts:
            if script.string:
                matches = api_regex.findall(script.string)
                for match in matches:
                    api_endpoints.add(match)

        return list(api_endpoints)
    except requests.RequestException:
        return []

def find_api_endpoints(domain: str) -> List[Dict]:
    """
    Busca endpoints de API probando patrones comunes en un dominio.
    """
    found_apis = []
    
    for path in API_PATTERNS:
        url = f"https://{domain}{path}"
        try:
            response = requests.get(url, timeout=5, headers=HEADERS)
            if response.status_code in [200, 401, 403]:
                found_apis.append({
                    'url': url,
                    'status_code': response.status_code,
                    'content_type': response.headers.get('Content-Type', '')
                })
        except requests.RequestException:
            continue
    
    return found_apis

def get_subdomains_crtsh(domain: str) -> List[str]:
    """
    Obtiene subdominios de un dominio usando crt.sh.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=5, headers=HEADERS)
        if response.status_code == 200:
            data = response.json()
            subdomains = {entry['name_value'] for entry in data}
            return list(subdomains)
    except requests.RequestException:
        pass
    return []

def find_all_apis(domain: str) -> List[Dict]:
    """
    Busca APIs en un dominio usando múltiples métodos.
    """
    apis = []
    
    # Buscar APIs en la página principal
    html_apis = find_api_in_html(f"https://{domain}")
    apis.extend([{'url': api, 'source': 'html_scan'} for api in html_apis])
    
    # Buscar APIs en endpoints comunes
    endpoint_apis = find_api_endpoints(domain)
    apis.extend([{**api, 'source': 'endpoint_scan'} for api in endpoint_apis])

    # Buscar APIs en subdominios
    subdomains = get_subdomains_crtsh(domain)
    for sub in subdomains:
        subdomain_apis = find_api_endpoints(sub)
        apis.extend([{**api, 'source': f'subdomain_scan:{sub}'} for api in subdomain_apis])

    # Eliminar duplicados manteniendo la información más completa
    unique_apis = {}
    for api in apis:
        url = api.get('url')
        if url not in unique_apis or len(api) > len(unique_apis[url]):
            unique_apis[url] = api

    return list(unique_apis.values())

@app.get("/")
async def root():
    """Endpoint raíz que muestra un mensaje de bienvenida"""
    return {"message": "Bienvenido a API Finder. Usa /docs para ver la documentación."}

@app.post("/find-apis/", response_model=APIResponse)
async def find_apis(domain_data: Domain):
    """
    Busca APIs en el dominio especificado.
    """
    try:
        domain = domain_data.domain
        api_list = find_all_apis(domain)
        
        return APIResponse(
            domain=domain,
            apis_found=api_list,
            total_found=len(api_list)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/check-endpoint/")
async def check_endpoint(url: HttpUrl):
    """
    Verifica si una URL es un endpoint de API.
    """
    try:
        response = requests.get(str(url), timeout=5, headers=HEADERS)
        return {
            "url": str(url),
            "status_code": response.status_code,
            "content_type": response.headers.get('Content-Type', ''),
            "is_api": any(pattern in str(url).lower() for pattern in API_PATTERNS)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/patterns/")
async def get_patterns():
    """Retorna la lista de patrones usados para identificar APIs"""
    return {"api_patterns": API_PATTERNS}