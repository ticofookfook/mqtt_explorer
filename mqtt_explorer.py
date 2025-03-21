"""
MQTT Explorer - Ferramenta de Análise de Segurança
--------------------------------------
Este script tenta explorar e analisar vulnerabilidades em brokers MQTT
através de conexão direta, tentativas de autenticação e enumeration de tópicos.
"""

import os
import re
import json
import socket
import ssl
import time
import random
import string
import logging
import argparse
import threading
from datetime import datetime
from queue import Queue

try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("Biblioteca Paho MQTT não encontrada. Instalando...")
    import subprocess
    subprocess.check_call(["pip", "install", "paho-mqtt"])
    import paho.mqtt.client as mqtt

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("mqtt_explorer.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Pasta para salvar resultados
RESULTS_DIR = "mqtt_exploration_results"
os.makedirs(RESULTS_DIR, exist_ok=True)

# Listas de usernames e passwords comuns para tentativa de brute force
COMMON_USERNAMES = [
    "",  # Sem autenticação
    "admin", "test", "user", "guest", "mqtt", "default", "system",
    "root", "device", "gwm", "haval", "tank", "service", "iot", 
    "broker", "sensor", "gateway", "vehicle", "car", "app",

]

COMMON_PASSWORDS = [
    "",  # Sem senha
    "admin", "password", "123456", "admin123", "test", "1234", "mqtt",
    "guest", "default", "12345678", "qwerty", "root", "gwm", "haval", 
    "tank", "iot123", "broker", "gateway123", "sensor123",
]

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

# Resultados da exploração
exploration_results = {
    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "targets": [],
    "vulnerable_targets": [],
    "discovered_topics": [],
    "intercepted_messages": []
}

# Mutex para proteger os resultados de exploração em threads concorrentes
results_lock = threading.Lock()

# Função de callback para conexão MQTT
def on_connect(client, userdata, flags, rc):
    connection_info = userdata.get("connection_info", {})
    host = connection_info.get("host", "unknown")
    port = connection_info.get("port", "unknown")
    username = connection_info.get("username", "")
    
    if rc == 0:
        result = f"Conectado com sucesso ao broker {host}:{port}"
        if username:
            result += f" com usuário '{username}'"
        logger.info(result)
        
        # Registrar conexão bem-sucedida nos resultados
        with results_lock:
            target_info = {
                "host": host,
                "port": port,
                "connection_successful": True,
                "username": username,
                "password": connection_info.get("password", ""),
                "use_ssl": connection_info.get("use_ssl", False),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            exploration_results["targets"].append(target_info)
            
            # Se a conexão foi bem-sucedida sem credenciais ou com credenciais fracas, registrar como vulnerável
            if not username or username in COMMON_USERNAMES[:5] and connection_info.get("password", "") in COMMON_PASSWORDS[:5]:
                target_info["vulnerability"] = "Conexão com credenciais fracas ou sem autenticação"
                exploration_results["vulnerable_targets"].append(target_info)
    else:
        rc_meanings = {
            1: "Conexão recusada - Versão de protocolo incorreta",
            2: "Conexão recusada - Identificador de cliente inválido",
            3: "Conexão recusada - Servidor indisponível",
            4: "Conexão recusada - Usuário ou senha incorretos",
            5: "Conexão recusada - Não autorizado"
        }
        
        error_msg = rc_meanings.get(rc, f"Falha na conexão com código desconhecido: {rc}")
        logger.warning(f"Falha ao conectar ao broker {host}:{port}: {error_msg}")
        
        # Registrar falha de conexão nos resultados
        with results_lock:
            target_info = {
                "host": host,
                "port": port,
                "connection_successful": False,
                "error_code": rc,
                "error_message": error_msg,
                "username": username,
                "password": connection_info.get("password", ""),
                "use_ssl": connection_info.get("use_ssl", False),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            exploration_results["targets"].append(target_info)

# Função de callback para mensagens recebidas
def on_message(client, userdata, msg):
    connection_info = userdata.get("connection_info", {})
    host = connection_info.get("host", "unknown")
    port = connection_info.get("port", "unknown")
    
    try:
        payload_str = msg.payload.decode('utf-8')
        logger.info(f"Mensagem recebida do tópico {msg.topic} de {host}:{port}: {payload_str[:100]}...")
        
        # Registrar mensagem interceptada
        with results_lock:
            message_info = {
                "host": host,
                "port": port,
                "topic": msg.topic,
                "payload": payload_str,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            exploration_results["intercepted_messages"].append(message_info)
            
            # Adicionar tópico descoberto se ainda não existir
            if msg.topic not in [t["topic"] for t in exploration_results["discovered_topics"]]:
                topic_info = {
                    "host": host,
                    "port": port,
                    "topic": msg.topic,
                    "discovery_method": "message_interception",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                exploration_results["discovered_topics"].append(topic_info)
    except Exception as e:
        logger.error(f"Erro ao processar mensagem de {host}:{port}: {e}")

# Função de callback para inscrição
def on_subscribe(client, userdata, mid, granted_qos):
    connection_info = userdata.get("connection_info", {})
    host = connection_info.get("host", "unknown")
    port = connection_info.get("port", "unknown")
    topic = userdata.get("current_topic", "unknown")
    
    logger.info(f"Inscrito no tópico {topic} em {host}:{port} com QoS {granted_qos}")
    
    # Registrar tópico descoberto
    with results_lock:
        topic_info = {
            "host": host,
            "port": port,
            "topic": topic,
            "discovery_method": "subscription",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        if topic_info not in exploration_results["discovered_topics"]:
            exploration_results["discovered_topics"].append(topic_info)

# Função para testar conexão com um broker MQTT
def test_mqtt_connection(host, port, username="", password="", use_ssl=False, timeout=5):
    logger.info(f"Testando conexão com {host}:{port} (SSL: {use_ssl}, Usuário: {username})")
    
    # Criar cliente MQTT com ID aleatório para evitar colisões
    client_id = f"mqtt-explorer-{random.randint(1000, 9999)}"
    client = mqtt.Client(client_id=client_id)
    
    # Configurar callbacks
    connection_info = {
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "use_ssl": use_ssl
    }
    userdata = {"connection_info": connection_info}
    client.user_data_set(userdata)
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_subscribe = on_subscribe
    
    # Configurar autenticação se fornecida
    if username:
        client.username_pw_set(username, password)
    
    # Configurar SSL se necessário
    if use_ssl:
        client.tls_set(cert_reqs=ssl.CERT_NONE)  # Não verificar certificado do servidor
        client.tls_insecure_set(True)
    
    # Tentar conexão
    try:
        client.connect(host, port, timeout)
        client.loop_start()
        
        # Aguardar conexão ser estabelecida ou falhar
        time.sleep(2)
        
        # Verificar se está conectado
        if client.is_connected():
            # Tentar se inscrever em tópicos comuns
            for topic in COMMON_TOPICS + AUTOMOTIVE_TOPICS:
                try:
                    userdata["current_topic"] = topic
                    client.user_data_set(userdata)
                    client.subscribe(topic)
                    time.sleep(0.5)  # Pequeno delay entre inscrições
                except Exception as e:
                    logger.warning(f"Erro ao se inscrever no tópico {topic}: {e}")
            
            # Aguardar mensagens por um curto período
            logger.info(f"Aguardando mensagens de {host}:{port}...")
            time.sleep(10)
            
            # Registrar conexão bem-sucedida (já feito no callback)
            result = True
        else:
            result = False
            
        # Desconectar cliente
        client.loop_stop()
        client.disconnect()
        
        return result
    except Exception as e:
        logger.warning(f"Erro ao conectar a {host}:{port}: {e}")
        
        # Registrar erro de conexão nos resultados (se não foi registrado no callback)
        with results_lock:
            connection_error = True
            for target in exploration_results["targets"]:
                if target["host"] == host and target["port"] == port and target.get("username", "") == username:
                    connection_error = False
                    break
            
            if connection_error:
                target_info = {
                    "host": host,
                    "port": port,
                    "connection_successful": False,
                    "error_message": str(e),
                    "username": username,
                    "password": password,
                    "use_ssl": use_ssl,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                exploration_results["targets"].append(target_info)
        
        try:
            client.loop_stop()
            client.disconnect()
        except:
            pass
        
        return False

# Função para testar múltiplas credenciais
def test_multiple_credentials(host, port, use_ssl=False):
    logger.info(f"Testando diferentes credenciais em {host}:{port}...")
    
    credentials_queue = Queue()
    
    # Adicionar combinações username/password à fila
    for username in COMMON_USERNAMES:
        # Primeiro tenta sem senha para cada username
        credentials_queue.put((username, ""))
        
        # Depois tenta com cada senha comum
        for password in COMMON_PASSWORDS:
            if password:  # Evitar duplicar a tentativa sem senha
                credentials_queue.put((username, password))
    
    # Função worker para threads
    def credential_worker():
        while not credentials_queue.empty():
            try:
                username, password = credentials_queue.get(block=False)
                test_mqtt_connection(host, port, username, password, use_ssl)
                time.sleep(1)  # Delay para evitar bloqueio por tentativas rápidas demais
            except Exception as e:
                logger.error(f"Erro no worker de credenciais: {e}")
            finally:
                credentials_queue.task_done()
    
    # Iniciar múltiplas threads para testar credenciais
    num_workers = min(10, credentials_queue.qsize())  # Limite de 10 threads
    threads = []
    
    for _ in range(num_workers):
        thread = threading.Thread(target=credential_worker)
        thread.daemon = True
        thread.start()
        threads.append(thread)
    
    # Aguardar todas as threads completarem
    for thread in threads:
        thread.join()

# Função para testar um único alvo MQTT
def explore_mqtt_target(host, port, use_ssl=False):
    logger.info(f"Explorando alvo MQTT: {host}:{port} (SSL: {use_ssl})")
    
    # Primeiro testar sem credenciais
    if test_mqtt_connection(host, port, "", "", use_ssl):
        logger.warning(f"Vulnerabilidade: {host}:{port} permite conexão sem autenticação!")
    
    # Testar múltiplas credenciais se o teste sem credenciais falhou
    test_multiple_credentials(host, port, use_ssl)

# Função principal para exploração de MQTT
def explore_mqtt_targets(targets):
    logger.info(f"Iniciando exploração de {len(targets)} alvos MQTT")
    
    # Inicializar resultados
    exploration_results["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    exploration_results["targets"] = []
    exploration_results["vulnerable_targets"] = []
    exploration_results["discovered_topics"] = []
    exploration_results["intercepted_messages"] = []
    
    # Explorar cada alvo
    for target in targets:
        host = target["host"]
        port = target.get("port", 1883)  # Porta padrão MQTT
        use_ssl = target.get("use_ssl", False)
        
        # Verificar se o host é válido
        try:
            socket.gethostbyname(host)
        except socket.gaierror:
            logger.error(f"Host inválido: {host}")
            continue
        
        explore_mqtt_target(host, port, use_ssl)
    
    # Salvar resultados
    output_file = os.path.join(RESULTS_DIR, f"mqtt_exploration_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(exploration_results, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Exploração concluída. Resultados salvos em: {output_file}")
    
    return exploration_results

# Função para analisar URL MQTT e extrair host, porta e SSL
def parse_mqtt_url(url):
    # Padrões para URLs MQTT
    mqtt_patterns = [
        re.compile(r'^mqtt://(?P<host>[^:/]+)(?::(?P<port>\d+))?'),
        re.compile(r'^mqtts://(?P<host>[^:/]+)(?::(?P<port>\d+))?'),
        re.compile(r'^ssl://(?P<host>[^:/]+)(?::(?P<port>\d+))?'),
        re.compile(r'^tcp://(?P<host>[^:/]+)(?::(?P<port>\d+))?'),
    ]
    
    # Se a URL não começa com um protocolo conhecido, assumir que é apenas o host
    if not (url.startswith('mqtt://') or url.startswith('mqtts://') or 
            url.startswith('ssl://') or url.startswith('tcp://')):
        url = 'mqtt://' + url
    
    # Verificar padrões
    for pattern in mqtt_patterns:
        match = pattern.match(url)
        if match:
            host = match.group('host')
            port_str = match.group('port')
            
            # Determinar porta e SSL com base no protocolo
            use_ssl = url.startswith('mqtts://') or url.startswith('ssl://')
            
            if port_str:
                port = int(port_str)
            else:
                port = 8883 if use_ssl else 1883  # Portas padrão
            
            return {"host": host, "port": port, "use_ssl": use_ssl}
    
    # Se chegou aqui, não conseguiu analisar a URL
    logger.error(f"Não foi possível analisar a URL MQTT: {url}")
    return None

# Análise avançada dos resultados para identificar vulnerabilidades mais críticas
def analyze_vulnerabilities(results):
    vulnerabilities = []
    
    # Verificar conexões sem autenticação
    for target in results["targets"]:
        if target.get("connection_successful", False) and not target.get("username"):
            vulnerabilities.append({
                "host": target["host"],
                "port": target["port"],
                "severity": "ALTA",
                "description": "Broker permite conexão sem autenticação",
                "recommendation": "Configurar autenticação obrigatória no broker MQTT"
            })
    
    # Verificar credenciais fracas
    for target in results["targets"]:
        if target.get("connection_successful", False) and target.get("username") in ["admin", "test", "guest", "mqtt"] and target.get("password") in ["admin", "password", "123456", "test", ""]:
            vulnerabilities.append({
                "host": target["host"],
                "port": target["port"],
                "severity": "ALTA",
                "description": f"Broker permite conexão com credenciais fracas (usuário: {target.get('username')}, senha: {target.get('password')})",
                "recommendation": "Implementar política de senhas fortes e remover contas padrão"
            })
    
    # Verificar acesso a tópicos sensíveis
    sensitive_topic_patterns = [
        re.compile(r"^\$SYS/.*"),  # Tópicos de sistema
        re.compile(r"^vehicle/.*/(command|control)"),  # Comandos de veículo
        re.compile(r".*/(password|credential|key|token).*"),  # Informações sensíveis
        re.compile(r".*/private/.*")  # Dados privados
    ]
    
    for topic_info in results["discovered_topics"]:
        for pattern in sensitive_topic_patterns:
            if pattern.match(topic_info["topic"]):
                vulnerabilities.append({
                    "host": topic_info["host"],
                    "port": topic_info["port"],
                    "severity": "MÉDIA",
                    "description": f"Acesso permitido a tópico sensível: {topic_info['topic']}",
                    "recommendation": "Implementar controle de acesso (ACL) adequado para tópicos sensíveis"
                })
                break
    
    # Verificar padrões sensíveis em mensagens interceptadas
    sensitive_patterns = [
        (re.compile(r"password|senha|passwd", re.IGNORECASE), "senha"),
        (re.compile(r"token|api.?key|secret", re.IGNORECASE), "token/chave de API"),
        (re.compile(r"lat.*lon|gps|coordinate", re.IGNORECASE), "localização"),
        (re.compile(r"ssn|cpf|passport|identidade|id.?number", re.IGNORECASE), "identificação pessoal")
    ]
    
    for message in results["intercepted_messages"]:
        for pattern, data_type in sensitive_patterns:
            if pattern.search(message["payload"]):
                vulnerabilities.append({
                    "host": message["host"],
                    "port": message["port"],
                    "severity": "CRÍTICA",
                    "description": f"Dados sensíveis ({data_type}) detectados em mensagem no tópico: {message['topic']}",
                    "recommendation": "Criptografar dados sensíveis antes da transmissão MQTT"
                })
                break
    
    # Remover duplicatas (mesma vulnerabilidade no mesmo host:porta)
    unique_vulnerabilities = []
    for vuln in vulnerabilities:
        if vuln not in unique_vulnerabilities:
            unique_vulnerabilities.append(vuln)
    
    return unique_vulnerabilities

# Gerar relatório HTML de vulnerabilidades
def generate_vulnerability_report(vulnerabilities, target_hosts):
    if not vulnerabilities:
        return None
    
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_file = os.path.join(RESULTS_DIR, f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    
    # Contar vulnerabilidades por severidade
    severity_counts = {"CRÍTICA": 0, "ALTA": 0, "MÉDIA": 0, "BAIXA": 0}
    for vuln in vulnerabilities:
        severity_counts[vuln["severity"]] = severity_counts.get(vuln["severity"], 0) + 1
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Vulnerabilidades MQTT</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }}
        h1, h2, h3 {{ color: #1a5276; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background-color: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .summary {{ display: flex; justify-content: space-between; margin-bottom: 20px; }}
        .summary-box {{ flex: 1; padding: 15px; border-radius: 5px; margin: 0 10px; color: white; }}
        .critical {{ background-color: #c0392b; }}
        .high {{ background-color: #e67e22; }}
        .medium {{ background-color: #f1c40f; color: #333; }}
        .low {{ background-color: #3498db; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .severity-tag {{ display: inline-block; padding: 5px 10px; border-radius: 3px; font-weight: bold; }}
        .footer {{ margin-top: 30px; font-size: 12px; color: #777; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Relatório de Vulnerabilidades MQTT</h1>
            <p>Gerado em: {report_time}</p>
            <p>Alvos analisados: {', '.join([f"{t['host']}:{t['port']}" for t in target_hosts[:5]])}{' e outros' if len(target_hosts) > 5 else ''}</p>
        </div>
        
        <div class="summary">
            <div class="summary-box critical">
                <h3>Críticas</h3>
                <h2>{severity_counts.get("CRÍTICA", 0)}</h2>
            </div>
            <div class="summary-box high">
                <h3>Altas</h3>
                <h2>{severity_counts.get("ALTA", 0)}</h2>
            </div>
            <div class="summary-box medium">
                <h3>Médias</h3>
                <h2>{severity_counts.get("MÉDIA", 0)}</h2>
            </div>
            <div class="summary-box low">
                <h3>Baixas</h3>
                <h2>{severity_counts.get("BAIXA", 0)}</h2>
            </div>
        </div>
        
        <h2>Vulnerabilidades Detectadas</h2>
        <table>
            <tr>
                <th>Servidor</th>
                <th>Severidade</th>
                <th>Descrição</th>
                <th>Recomendação</th>
            </tr>
    """
    
    # Ordenar vulnerabilidades por severidade (crítica primeiro)
    severity_order = {"CRÍTICA": 0, "ALTA": 1, "MÉDIA": 2, "BAIXA": 3}
    sorted_vulnerabilities = sorted(vulnerabilities, key=lambda x: severity_order.get(x["severity"], 4))
    
    for vuln in sorted_vulnerabilities:
        severity_class = {
            "CRÍTICA": "critical",
            "ALTA": "high",
            "MÉDIA": "medium",
            "BAIXA": "low"
        }.get(vuln["severity"], "low")
        
        html += f"""
            <tr>
                <td>{vuln["host"]}:{vuln["port"]}</td>
                <td><span class="severity-tag {severity_class}">{vuln["severity"]}</span></td>
                <td>{vuln["description"]}</td>
                <td>{vuln["recommendation"]}</td>
            </tr>
        """
    
    html += """
        </table>
        
        <div class="footer">
            <p>Este relatório foi gerado automaticamente pela ferramenta MQTT Explorer.</p>
            <p>As vulnerabilidades relatadas devem ser verificadas manualmente antes de implementar correções.</p>
        </div>
    </div>
</body>
</html>
    """
    
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(html)
    
    return report_file

# Função principal
def main():
    parser = argparse.ArgumentParser(description="MQTT Explorer - Ferramenta de Análise de Segurança")
    parser.add_argument("--url", type=str, help="URL MQTT única para explorar (formato: mqtt://host:port ou mqtts://host:port)")
    parser.add_argument("--url-file", type=str, help="Arquivo contendo lista de URLs MQTT para explorar (uma por linha)")
    parser.add_argument("--host", type=str, help="Host MQTT para explorar")
    parser.add_argument("--port", type=int, default=1883, help="Porta MQTT (padrão: 1883)")
    parser.add_argument("--ssl", action="store_true", help="Usar SSL/TLS para conexão")
    parser.add_argument("--report", action="store_true", help="Gerar relatório HTML de vulnerabilidades")
    args = parser.parse_args()
    
    logger.info("Iniciando MQTT Explorer")
    
    # Lista de alvos para explorar
    targets = []
    
    # Adicionar alvo de URL única
    if args.url:
        target = parse_mqtt_url(args.url)
        if target:
            targets.append(target)
    
    # Adicionar alvos de arquivo
    if args.url_file:
        try:
            with open(args.url_file, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith('#'):  # Ignorar linhas vazias e comentários
                        target = parse_mqtt_url(url)
                        if target:
                            targets.append(target)
        except Exception as e:
            logger.error(f"Erro ao ler arquivo de URLs: {e}")
    
    # Adicionar alvo de parâmetros host/port
    if args.host:
        targets.append({
            "host": args.host,
            "port": args.port,
            "use_ssl": args.ssl
        })
    
    # Se nenhum alvo foi especificado, mostrar ajuda
    if not targets:
        parser.print_help()
        logger.error("Nenhum alvo MQTT especificado. Use --url, --url-file ou --host.")
        return
    
    # Mostrar alvos
    logger.info(f"Alvos MQTT para exploração:")
    for i, target in enumerate(targets, 1):
        logger.info(f"{i}. {target['host']}:{target['port']} (SSL: {target['use_ssl']})")
    
    # Executar exploração
    results = explore_mqtt_targets(targets)
    
    # Analisar vulnerabilidades
    vulnerabilities = analyze_vulnerabilities(results)
    
    # Gerar relatório de vulnerabilidades
    if args.report or True:  # Sempre gerar relatório
        report_file = generate_vulnerability_report(vulnerabilities, targets)
        if report_file:
            logger.info(f"Relatório de vulnerabilidades gerado: {report_file}")
    
    # Exibir resumo
    logger.info("Resumo da exploração:")
    
    vulnerable_count = len(results["vulnerable_targets"])
    if vulnerable_count > 0:
        logger.warning(f"Encontrados {vulnerable_count} alvos vulneráveis:")
        for i, target in enumerate(results["vulnerable_targets"], 1):
            vuln_info = f"{i}. {target['host']}:{target['port']}"
            if "vulnerability" in target:
                vuln_info += f" - {target['vulnerability']}"
            logger.warning(vuln_info)
    else:
        logger.info("Nenhum alvo vulnerável encontrado.")
    
    topic_count = len(results["discovered_topics"])
    if topic_count > 0:
        logger.info(f"Descobertos {topic_count} tópicos:")
        for i, topic_info in enumerate(results["discovered_topics"][:10], 1):  # Mostrar apenas os 10 primeiros
            logger.info(f"{i}. {topic_info['topic']} em {topic_info['host']}:{topic_info['port']}")
        if topic_count > 10:
            logger.info(f"... e mais {topic_count - 10} tópicos")
    else:
        logger.info("Nenhum tópico descoberto.")
    
    message_count = len(results["intercepted_messages"])
    if message_count > 0:
        logger.info(f"Interceptadas {message_count} mensagens.")
    else:
        logger.info("Nenhuma mensagem interceptada.")
    
    # Exibir resumo de vulnerabilidades
    if vulnerabilities:
        severity_counts = {"CRÍTICA": 0, "ALTA": 0, "MÉDIA": 0, "BAIXA": 0}
        for vuln in vulnerabilities:
            severity_counts[vuln["severity"]] = severity_counts.get(vuln["severity"], 0) + 1
        
        logger.warning("Vulnerabilidades detectadas:")
        for severity in ["CRÍTICA", "ALTA", "MÉDIA", "BAIXA"]:
            if severity_counts.get(severity, 0) > 0:
                logger.warning(f"  - {severity}: {severity_counts[severity]}")
    
    logger.info(f"Resultados completos salvos em: {RESULTS_DIR}")

if __name__ == "__main__":
    main()