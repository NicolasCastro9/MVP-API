import subprocess
import time


agente_owasp_cmd = ["python", "-m", "uvicorn", "Agente_Owasp:app", "--host", "127.0.0.1", "--port", "8001", "--reload"]
process1 = subprocess.Popen(agente_owasp_cmd)
time.sleep(2)
try:
    process1.wait()
except KeyboardInterrupt:
    print("Deteniendo APIs...")
    process1.terminate()

