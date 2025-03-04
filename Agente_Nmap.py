from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Puedes restringirlo a ["http://localhost:5500"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    domain: str

def scan_ports(domain: str):
    """Escaneo detallado de puertos con Nmap."""
    try:
        result = subprocess.run(["nmap", domain], capture_output=True, text=True)
        return {"domain": domain, "ports_output": result.stdout}
    except Exception as e:
        return {"error": str(e)}

@app.post("/scan-ports")
def scan_ports_api(request: ScanRequest):
    if not request.domain:
        raise HTTPException(status_code=400, detail="No domain provided")
    return scan_ports(request.domain)

