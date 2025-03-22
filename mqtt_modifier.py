"""
MQTT Modifier - Módulo para intercepção e modificação de mensagens MQTT
---------------------------------------------------------------------
Este módulo permite interceptar, modificar e injetar mensagens em brokers MQTT,
complementando as funcionalidades de análise de segurança do MQTT Explorer.
"""

import json
import time
import random
import ssl
import logging
import paho.mqtt.client as mqtt
from datetime import datetime

# Configuração de logging
logger = logging.getLogger(__name__)

class MQTTModifier:
    def __init__(self, host, port, username="", password="", use_ssl=False):
        """
        Inicializa o modificador MQTT.
        
        :param host: Endereço do broker MQTT
        :param port: Porta do broker MQTT
        :param username: Nome de usuário para autenticação (opcional)
        :param password: Senha para autenticação (opcional)
        :param use_ssl: Indica se deve usar conexão SSL/TLS
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.client = None
        self.connected = False
        self.intercepted_count = 0
        self.modified_count = 0
        
    def connect(self, timeout=10):
        """
        Conecta ao broker MQTT.
        
        :param timeout: Tempo máximo de espera para conexão em segundos
        :return: True se conectado com sucesso, False caso contrário
        """
        try:
            client_id = f"mqtt-modifier-{random.randint(1000, 9999)}"
            self.client = mqtt.Client(client_id=client_id)
            
            # Configurar callbacks
            self.client.on_connect = self._on_connect
            self.client.on_disconnect = self._on_disconnect
            
            # Configurar autenticação se fornecida
            if self.username:
                self.client.username_pw_set(self.username, self.password)
            
            # Configurar SSL se necessário
            if self.use_ssl:
                self.client.tls_set(cert_reqs=ssl.CERT_NONE)
                self.client.tls_insecure_set(True)
            
            # Conectar
            self.client.connect(self.host, self.port, 60)
            self.client.loop_start()
            
            # Aguardar conexão
            start_time = time.time()
            while not self.connected and time.time() - start_time < timeout:
                time.sleep(0.1)
            
            if not self.connected:
                raise Exception("Timeout ao conectar ao broker MQTT")
                
            return True
        
        except Exception as e:
            logger.error(f"Erro ao conectar para modificação: {e}")
            return False
    
    def _on_connect(self, client, userdata, flags, rc):
        """Callback chamado quando a conexão é estabelecida"""
        if rc == 0:
            self.connected = True
            logger.info(f"Conectado ao broker {self.host}:{self.port} para modificação")
        else:
            rc_meanings = {
                1: "Versão de protocolo incorreta",
                2: "Identificador de cliente inválido",
                3: "Servidor indisponível",
                4: "Usuário ou senha incorretos",
                5: "Não autorizado"
            }
            error_msg = rc_meanings.get(rc, f"Código desconhecido: {rc}")
            logger.error(f"Falha ao conectar para modificação: {error_msg}")
    
    def _on_disconnect(self, client, userdata, rc):
        """Callback chamado quando a conexão é encerrada"""
        self.connected = False
        if rc == 0:
            logger.info(f"Desconectado normalmente do broker {self.host}:{self.port}")
        else:
            logger.warning(f"Desconexão inesperada do broker {self.host}:{self.port}, código: {rc}")
    
    def publish_message(self, topic, payload, qos=0, retain=False):
        """
        Publica uma mensagem em um tópico específico.
        
        :param topic: Tópico para publicação
        :param payload: Conteúdo da mensagem
        :param qos: Quality of Service (0, 1 ou 2)
        :param retain: Flag para mensagem retida
        :return: True se publicado com sucesso, False caso contrário
        """
        if not self.connected:
            logger.error("Não conectado ao broker MQTT")
            return False
        
        try:
            result = self.client.publish(topic, payload, qos, retain)
            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                logger.info(f"Mensagem publicada com sucesso no tópico: {topic}")
                return True
            else:
                logger.error(f"Erro ao publicar mensagem: {mqtt.error_string(result.rc)}")
                return False
        except Exception as e:
            logger.error(f"Exceção ao publicar mensagem: {e}")
            return False
    
    def start_interception(self, topic_filters=["#"], modifier_func=None, republish=True, prefix="modified"):
        """
        Inicia a interceptação e modificação de mensagens.
        
        :param topic_filters: Lista de tópicos para interceptar
        :param modifier_func: Função opcional que recebe (topic, payload) e retorna payload modificado
        :param republish: Se True, republica mensagens modificadas
        :param prefix: Prefixo para tópicos das mensagens modificadas
        :return: True se iniciado com sucesso, False caso contrário
        """
        if not self.connected:
            logger.error("Não conectado ao broker MQTT")
            return False
        
        def on_message(client, userdata, msg):
            try:
                topic = msg.topic
                payload = msg.payload.decode('utf-8')
                self.intercepted_count += 1
                logger.info(f"[{self.intercepted_count}] Interceptada mensagem no tópico {topic}: {payload[:100]}...")
                
                if modifier_func:
                    # Usar a função personalizada para modificar o payload
                    modified_payload = modifier_func(topic, payload)
                else:
                    # Modificação padrão - tentar JSON ou texto
                    try:
                        data = json.loads(payload)
                        # Adicionar marcadores de modificação
                        data["modified"] = True
                        data["modified_timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        data["modified_by"] = "mqtt_explorer"
                        modified_payload = json.dumps(data)
                    except json.JSONDecodeError:
                        # Se não for JSON, adicionar marcador ao texto
                        modified_payload = f"{payload} [Modificado em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]"
                
                # Republicar a mensagem modificada se configurado
                if republish:
                    self.modified_count += 1
                    new_topic = f"{prefix}/{topic}" if prefix else topic
                    self.publish_message(new_topic, modified_payload, msg.qos)
                    logger.info(f"[{self.modified_count}] Republicada mensagem modificada em {new_topic}")
                
            except Exception as e:
                logger.error(f"Erro ao processar mensagem interceptada: {e}")
        
        # Configurar callback e inscrever-se
        self.client.on_message = on_message
        for topic in topic_filters:
            self.client.subscribe(topic)
            logger.info(f"Inscrito para interceptação no tópico: {topic}")
        
        logger.info(f"Interceptação iniciada em {self.host}:{self.port}. Mensagens serão {'modificadas e republicadas' if republish else 'apenas interceptadas'}.")
        return True
    
    def inject_message_stream(self, topic, message_generator, interval=1.0, count=10):
        """
        Injeta uma série de mensagens geradas em um tópico.
        
        :param topic: Tópico para injeção
        :param message_generator: Função que gera mensagens (sem argumentos)
        :param interval: Intervalo entre mensagens em segundos
        :param count: Número de mensagens a injetar (0 para infinito)
        """
        if not self.connected:
            logger.error("Não conectado ao broker MQTT")
            return False
        
        logger.info(f"Iniciando injeção de mensagens no tópico {topic}")
        
        try:
            i = 0
            while count == 0 or i < count:
                message = message_generator()
                self.publish_message(topic, message)
                time.sleep(interval)
                i += 1
                
            logger.info(f"Injeção de mensagens concluída: {i} mensagens enviadas para {topic}")
            return True
            
        except KeyboardInterrupt:
            logger.info(f"Injeção interrompida pelo usuário após {i} mensagens")
            return True
        except Exception as e:
            logger.error(f"Erro durante injeção de mensagens: {e}")
            return False
    
    def stop(self):
        """Encerra a conexão com o broker MQTT"""
        if self.client:
            self.client.loop_stop()
            self.client.disconnect()
            logger.info(f"Modificador MQTT desconectado de {self.host}:{self.port}")
            return True
        return False

# Algumas funções de modificação pré-definidas
def json_field_modifier(field_name, new_value):
    """
    Retorna uma função que modifica um campo específico em mensagens JSON.
    
    :param field_name: Nome do campo a modificar
    :param new_value: Novo valor para o campo
    :return: Função de modificação
    """
    def modifier(topic, payload):
        try:
            data = json.loads(payload)
            if field_name in data:
                data[field_name] = new_value
            return json.dumps(data)
        except:
            return payload
    return modifier

def json_value_multiplier(field_name, multiplier=2.0):
    """
    Retorna uma função que multiplica o valor de um campo numérico em mensagens JSON.
    
    :param field_name: Nome do campo a modificar
    :param multiplier: Fator de multiplicação
    :return: Função de modificação
    """
    def modifier(topic, payload):
        try:
            data = json.loads(payload)
            if field_name in data and isinstance(data[field_name], (int, float)):
                data[field_name] = data[field_name] * multiplier
            return json.dumps(data)
        except:
            return payload
    return modifier

# Exemplo de uso
if __name__ == "__main__":
    # Configurar logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Exemplo: conectar a um broker e modificar mensagens
    modifier = MQTTModifier("test.mosquitto.org", 1883)
    if modifier.connect():
        # Iniciar interceptação com modificador personalizado
        modifier.start_interception(
            topic_filters=["#"],
            modifier_func=json_field_modifier("status", "hacked")
        )
        
        try:
            # Manter o programa em execução
            print("Pressione Ctrl+C para encerrar...")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Encerrando...")
        
        modifier.stop()
