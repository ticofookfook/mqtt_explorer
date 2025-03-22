"""
Gerador de relatórios para o MQTT Explorer
Funções para análise de vulnerabilidades e geração de relatórios
"""

import re
import os
import json
import threading
from datetime import datetime
import logging

# Configuração de logging
logger = logging.getLogger(__name__)

# Importar pasta de resultados do config
from config import RESULTS_DIR, GENERATE_REPORT

# Mutex para proteger os resultados de exploração em threads concorrentes
results_lock = threading.Lock()

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
        logger.info("Nenhuma vulnerabilidade encontrada para gerar relatório.")
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
    
    logger.info(f"Relatório de vulnerabilidades gerado: {report_file}")
    return report_file

# Função para salvar resultados e gerar relatório
def save_and_report_results(exploration_results, target_hosts):
    # Salvar resultados em JSON
    output_file = os.path.join(RESULTS_DIR, f"mqtt_exploration_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(exploration_results, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Resultados da exploração salvos em: {output_file}")
    
    # Analisar vulnerabilidades
    vulnerabilities = analyze_vulnerabilities(exploration_results)
    
    # Gerar relatório HTML se configurado para isso
    if GENERATE_REPORT:
        report_file = generate_vulnerability_report(vulnerabilities, target_hosts)
        if report_file:
            logger.info(f"Relatório de vulnerabilidades gerado: {report_file}")
    
    # Exibir resumo das vulnerabilidades
    if vulnerabilities:
        severity_counts = {"CRÍTICA": 0, "ALTA": 0, "MÉDIA": 0, "BAIXA": 0}
        for vuln in vulnerabilities:
            severity_counts[vuln["severity"]] = severity_counts.get(vuln["severity"], 0) + 1
        
        logger.warning("Vulnerabilidades detectadas:")
        for severity in ["CRÍTICA", "ALTA", "MÉDIA", "BAIXA"]:
            if severity_counts.get(severity, 0) > 0:
                logger.warning(f"  - {severity}: {severity_counts[severity]}")
                
    return vulnerabilities, output_file
