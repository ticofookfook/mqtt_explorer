#!/bin/bash
# Script para executar o MQTT Explorer com diferentes opções

# Cores para saída
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}===== MQTT Explorer - Ferramenta de Análise de Segurança =====${NC}"
echo

# Verificar se o Python está instalado
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Python3 não encontrado. Por favor, instale-o primeiro.${NC}"
    exit 1
fi

# Verificar se o script principal existe
if [ ! -f mqtt_explorer.py ]; then
    echo -e "${RED}Script mqtt_explorer.py não encontrado no diretório atual.${NC}"
    exit 1
fi

# Verificar se o arquivo de URLs existe
if [ ! -f mqtt_urls.txt ]; then
    echo -e "${YELLOW}Arquivo mqtt_urls.txt não encontrado. Apenas o modo URL única ou host direto será possível.${NC}"
fi

# Menu de opções
echo "Escolha uma opção de execução:"
echo "1) Explorar URL única"
echo "2) Explorar a partir de arquivo de URLs"
echo "3) Explorar host específico"
echo "4) Sair"
echo
read -p "Opção [1-4]: " option

case $option in
    1)
        read -p "Digite a URL MQTT (ex: mqtt://exemplo.com:1883): " mqtt_url
        echo -e "${GREEN}Executando exploração para URL única: ${mqtt_url}${NC}"
        python3 mqtt_explorer.py --url "$mqtt_url"
        ;;
    2)
        if [ -f mqtt_urls.txt ]; then
            echo -e "${GREEN}Executando exploração a partir do arquivo mqtt_urls.txt${NC}"
            python3 mqtt_explorer.py --url-file mqtt_urls.txt
        else
            echo -e "${RED}Arquivo mqtt_urls.txt não encontrado.${NC}"
            exit 1
        fi
        ;;
    3)
        read -p "Digite o host MQTT: " mqtt_host
        read -p "Digite a porta MQTT [1883]: " mqtt_port
        mqtt_port=${mqtt_port:-1883}
        
        read -p "Usar SSL? (s/n) [n]: " use_ssl
        use_ssl=${use_ssl:-n}
        
        if [[ $use_ssl == "s" || $use_ssl == "S" ]]; then
            ssl_flag="--ssl"
        else
            ssl_flag=""
        fi
        
        echo -e "${GREEN}Executando exploração para host: ${mqtt_host}:${mqtt_port} ${ssl_flag}${NC}"
        python3 mqtt_explorer.py --host "$mqtt_host" --port "$mqtt_port" $ssl_flag
        ;;
    4)
        echo -e "${YELLOW}Saindo.${NC}"
        exit 0
        ;;
    *)
        echo -e "${RED}Opção inválida.${NC}"
        exit 1
        ;;
esac

echo -e "${GREEN}===== Exploração concluída =====${NC}"