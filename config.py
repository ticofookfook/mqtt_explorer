"""
Configurações e constantes para o MQTT Explorer
"""

import os
from dotenv import load_dotenv

# Carregar variáveis do arquivo .env
load_dotenv()

# Pasta para salvar resultados
RESULTS_DIR = os.getenv("REPORT_DIR", "mqtt_exploration_results")
os.makedirs(RESULTS_DIR, exist_ok=True)

# Configurações de autenticação - carregadas do arquivo .env
# Filtra valores vazios e remove espaços em branco
COMMON_USERNAMES = [username.strip() for username in os.getenv("USERNAMES", "").split(",") if username.strip()]
COMMON_PASSWORDS = [password.strip() for password in os.getenv("PASSWORDS", "").split(",") if password.strip()]

# Adicionar opção vazia (sem username/password) se não estiver na lista
if "" not in COMMON_USERNAMES:
    COMMON_USERNAMES.insert(0, "")
if "" not in COMMON_PASSWORDS:
    COMMON_PASSWORDS.insert(0, "")

# Configurações de exploração
MAX_THREADS = int(os.getenv("MAX_THREADS", "10"))
TIMEOUT = int(os.getenv("TIMEOUT", "5"))
WAIT_TIME = int(os.getenv("WAIT_TIME", "10"))

# Configurações de relatório
GENERATE_REPORT = os.getenv("GENERATE_REPORT", "true").lower() == "true"

# Tópicos comuns para tentar se inscrever
COMMON_TOPICS = [
    "#",  # Wildcard para todos os tópicos
    "+/#",  # Wildcard para todos os tópicos de segundo nível
    "vehicle/#",
    "car/#", 
    "sensor/#",
    "device/#",
    "status/#",
    "telemetry/#",
    "location/#",
    "command/#",
    "control/#",
    "data/#",
    "gwm/#",
    "haval/#",
    "tank/#",
    "ora/#",
    "info/#",
    "system/#",
    "$SYS/#",  # Tópicos do sistema (usado por muitos brokers)
    "iot/#"
]

# Tópicos específicos para aplicativos automotivos
AUTOMOTIVE_TOPICS = [
    "vehicle/+/status",
    "vehicle/+/command",
    "vehicle/+/telemetry",
    "vehicle/+/location",
    "vehicle/+/engine",
    "vehicle/+/battery",
    "vehicle/+/doors",
    "vehicle/+/climate",
    "vehicle/+/lights",
    "vehicle/+/firmware",
    "fleet/+/status",
    "user/+/vehicle/+",
    "vin/+/data",
    
    # Tópicos específicos GWM/HAVAL
    "gwm/+/vehicle/+/data",
    "haval/+/vehicle/+/data",
    "tank/+/vehicle/+/data",
    "ora/+/vehicle/+/data",
    "gwm/device/+/status",
    "haval/device/+/status",
    "gwm/+/ota/status",
    "haval/+/ota/status",
    "gwm/command/+",
    "haval/command/+",
    "gwm/response/+",
    "haval/response/+",
    "gwm/app/+/request",
    "haval/app/+/request",
    "gwm/app/+/response",
    "haval/app/+/response",
    "user/+/gwm/+",
    "user/+/haval/+",
    "car/data/+",
    "car/control/+",
    "car/status/+",
    "car/location/+",
    "vehicle/data/gwm/+",
    "vehicle/data/haval/+",
    "vehicle/data/tank/+",
    "vehicle/data/ora/+",
    "data/vehicle/+",
    "command/vehicle/+",
    "response/vehicle/+",
    "telemetry/+",
    "diagnostics/+",
    "tracker/+",
    "location/+/update",
    "control/+/request",
    "control/+/response"
]
