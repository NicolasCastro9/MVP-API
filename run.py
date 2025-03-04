import subprocess
import time

# Comandos para ejecutar las tres APIs
api_finder_cmd = ["uvicorn", "Api_finder_api:app", "--host", "127.0.0.1", "--port", "8000", "--reload"]
agente_owasp_cmd = ["uvicorn", "Agente_Owasp:app", "--host", "127.0.0.1", "--port", "8001", "--reload"]
agente_nmap_cmd = ["uvicorn", "Agente_Nmap:app", "--host", "127.0.0.1", "--port", "8002", "--reload"]

# Ejecutar los procesos en paralelo
process1 = subprocess.Popen(api_finder_cmd)
time.sleep(2)  # Pequeño retraso para evitar conflictos de puertos
process2 = subprocess.Popen(agente_owasp_cmd)
time.sleep(2)
process3 = subprocess.Popen(agente_nmap_cmd)

# Mantener el script en ejecución
try:
    process1.wait()
    process2.wait()
    process3.wait()
except KeyboardInterrupt:
    print("Deteniendo APIs...")
    process1.terminate()
    process2.terminate()
    process3.terminate()
