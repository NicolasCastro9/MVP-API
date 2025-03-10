import subprocess
import time

# Comandos para ejecutar las APIs
api_finder_cmd = ["python", "-m", "uvicorn", "Api_finder_api:app", "--host", "127.0.0.1", "--port", "8000", "--reload"]
agente_owasp_cmd = ["python", "-m", "uvicorn", "Agente_Owasp:app", "--host", "127.0.0.1", "--port", "8001", "--reload"]
agente_nmap_cmd = ["python", "-m", "uvicorn", "Agente_Nmap:app", "--host", "127.0.0.1", "--port", "8002", "--reload"]
api_f_Dorking_cmd = ["python", "-m", "uvicorn", "Buscar_API:app", "--host", "127.0.0.1", "--port", "8003", "--reload"]

# Ejecutar los procesos en paralelo
process1 = subprocess.Popen(api_finder_cmd)
time.sleep(2)
process2 = subprocess.Popen(agente_owasp_cmd)
time.sleep(2)
process3 = subprocess.Popen(agente_nmap_cmd)
time.sleep(2)
process4 = subprocess.Popen(api_f_Dorking_cmd)

# Mantener el script en ejecución
try:
    process1.wait()
    process2.wait()
    process3.wait()
    process4.wait()
except KeyboardInterrupt:
    print("Deteniendo APIs...")
    process1.terminate()
    process2.terminate()
    process3.terminate()
    process4.terminate()
