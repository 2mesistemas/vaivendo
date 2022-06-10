#!/bin/bash

# Cores dos textos

NOCOLOR='\033[0m'
RED='\033[1;31m'
GREEN='\033[1;32m'
ORANGE='\033[1;33m'
BLUE='\033[1;34m'
PURPLE='\033[1;35m'
CYAN='\033[1;36m'
LIGHTGRAY='\033[1;37m'
DARKGRAY='\033[1;30m'
LIGHTRED='\033[1;31m'
LIGHTGREEN='\033[1;32m'
YELLOW='\033[1;33m'
LIGHTBLUE='\033[1;34m'
LIGHTPURPLE='\033[1;35m'
LIGHTCYAN='\033[1;36m'
WHITE='\033[1;37m'

# Codificando os caracteres das senhas para URL Encode

urlencode() {
    local LC_ALL=C
    local string="$*"
    local length="${#string}"
    local char
    local char2
    
    urlencoded=''

    for (( i = 0; i < length; i++ )); do
        char="${string:i:1}"
        if [[ "$char" == [a-zA-Z0-9.~_-] ]]; then
            char2=$(printf "$char")
            urlencoded="${urlencoded}${char2}"
        else
            char2=$(printf '%%%02X' "'$char")
            urlencoded="${urlencoded}${char2}"
        fi
    done
}

urlencode_systemctl() {
    local LC_ALL=C
    local string="$*"
    local length="${#string}"
    local char
    local char2
    
    urlencoded_systemctl=''

    for (( i = 0; i < length; i++ )); do
        char="${string:i:1}"
        if [[ "$char" == [a-zA-Z0-9.~_-] ]]; then
            char2=$(printf "$char")
            urlencoded_systemctl="${urlencoded_systemctl}${char2}"
        else
            char2=$(printf '%%%%%02X' "'$char")
            urlencoded_systemctl="${urlencoded_systemctl}${char2}"
        fi
    done
}

# Lendo o nome completo

echo "Digite o seu nome completo:"
read nome_completo;

nome_completo=${nome_completo/'@tjrj.jus.br'/''}

# Lendo o usuario de rede

echo "Digite o seu usuario de rede:"
read usuario_de_rede;

usuario_de_rede=${usuario_de_rede/'@tjrj.jus.br'/''}
usuario_de_rede_com_host="${usuario_de_rede}@tjrj.jus.br"

# Lendo o senha do usuario de rede

echo "Digite sua senha do usuario de rede:"
read senha_do_usario_rede

urlencode $senha_do_usario_rede
senha_do_usario_rede_codificada=$urlencoded

urlencode_systemctl $senha_do_usario_rede
senha_do_usario_rede_codificada_systemctl=$urlencoded_systemctl

proxy_codificado="http://${usuario_de_rede}:${senha_do_usario_rede_codificada}@proxy:80"
proxy_codificado_com_escape="http:\/\/${usuario_de_rede}:${senha_do_usario_rede_codificada}@proxy:80"
proxy_codificado_com_escape_systemctl="http:\/\/${usuario_de_rede}:${senha_do_usario_rede_codificada_systemctl}@proxy:80"

echo -e ""

# Configurando o arquivo .gitconfig

echo -e ${LIGHTBLUE}"Configurando arquivo .gitconfig..."${NOCOLOR}
git config --system user.name "$nome_completo"
git config --system user.email "$usuario_de_rede_com_host"
git config --system http.proxy "$proxy_codificado"
git config --system https.proxy "$proxy_codificado"
git config --system http.sslVerify false
git config --system https.sslVerify false
echo -e ${GREEN}"Arquivo .gitconfig configurado!"${NOCOLOR}

# Configurando o arquivo /home/$SUDO_USER/.profile

echo -e ${LIGHTBLUE}"Configurando arquivo /home/$SUDO_USER/.profile..."${NOCOLOR}
environment_http_proxy_regex="http_proxy=http:\/\/.*:.*@proxy:80"
environment_https_proxy_regex="https_proxy=http:\/\/.*:.*@proxy:80"
environment_ftp_proxy_regex="ftp_proxy=http:\/\/.*:.*@proxy:80"
sed_environment_http_string="s/${environment_http_proxy_regex}/http_proxy=${proxy_codificado_com_escape}/"
sed_environment_https_string="s/${environment_https_proxy_regex}/https_proxy=${proxy_codificado_com_escape}/"
sed_environment_ftp_string="s/${environment_ftp_proxy_regex}/ftp_proxy=${proxy_codificado_com_escape}/"
sed -i $sed_environment_http_string /home/$SUDO_USER/.profile
sed -i $sed_environment_https_string /home/$SUDO_USER/.profile
sed -i $sed_environment_ftp_string /home/$SUDO_USER/.profile
source /home/$SUDO_USER/.profile
echo -e ${GREEN}"Arquivo /home/$SUDO_USER/.profile configurado!"${NOCOLOR}

# Configurando o arquivo settings.xml

echo -e ${LIGHTBLUE}"Configurando arquivo settings.xml..."${NOCOLOR}
xmlstarlet_settings_m2="ed --inplace -N x="http://maven.apache.org/SETTINGS/1.1.0" -u "/x:settings/x:proxies/x:proxy/x:username" -v ${usuario_de_rede} -u "/x:settings/x:proxies/x:proxy/x:password" -v ${senha_do_usario_rede} /home/$SUDO_USER/.m2/settings.xml"
xmlstarlet $xmlstarlet_settings_m2
echo -e ${GREEN}"Arquivo settings.xml configurado!"${NOCOLOR}

# Configurando o arquivo config.json

echo -e ${LIGHTBLUE}"Configurando arquivo config.json..."${NOCOLOR}
cat <<< $(jq -c --arg proxy_codificado_jq "${proxy_codificado}" '.proxies.default.httpProxy = $proxy_codificado_jq' /home/$SUDO_USER/.docker/config.json) > /home/$SUDO_USER/.docker/config.json
cat <<< $(jq -c --arg proxy_codificado_jq "${proxy_codificado}" '.proxies.default.httpsProxy = $proxy_codificado_jq' /home/$SUDO_USER/.docker/config.json) > /home/$SUDO_USER/.docker/config.json
chmod 666 /home/$SUDO_USER/.docker/config.json
echo -e ${GREEN}"Arquivo config.json configurado!"${NOCOLOR}

# Configurando o arquivo http-proxy.conf

echo -e ${LIGHTBLUE}"Configurando arquivo http-proxy.conf..."${NOCOLOR}
http_proxy_conf_regex="Environment=\"HTTP_PROXY=http:\/\/.*:.*@proxy:80\""
sed_http_proxy_conf_string="s/${http_proxy_conf_regex}/Environment=\"HTTP_PROXY=${proxy_codificado_com_escape_systemctl}\"/"
sed -i $sed_http_proxy_conf_string /etc/systemd/system/docker.service.d/http-proxy.conf
echo -e ${GREEN}"Arquivo http-proxy.conf configurado!"${NOCOLOR}

# Configurando o arquivo https-proxy.conf

echo -e ${LIGHTBLUE}"Configurando arquivo https-proxy.conf..."${NOCOLOR}
https_proxy_conf_regex="Environment=\"HTTPS_PROXY=http:\/\/.*:.*@proxy:80\""
sed_https_proxy_conf_string="s/${https_proxy_conf_regex}/Environment=\"HTTPS_PROXY=${proxy_codificado_com_escape_systemctl}\"/"
sed -i $sed_https_proxy_conf_string /etc/systemd/system/docker.service.d/https-proxy.conf
echo -e ${GREEN}"Arquivo https-proxy.conf configurado!"${NOCOLOR}

# Reinicia o docker para pegar as mudancas nos arquivos de configuracoes

echo -e ${LIGHTBLUE}"Reiniciando o docker para pegar as mudancas nos arquivos de configuracoes..."${NOCOLOR}
sudo systemctl daemon-reload
sudo systemctl restart docker
systemctl is-active --quiet docker && echo -e ${GREEN}"Docker esta ativo!"${NOCOLOR} || echo -e ${RED}"Docker esta inativo!"${NOCOLOR}
echo -e ${GREEN}"Reinicializacao do docker completa!"${NOCOLOR}

# Aviso para configurar o proxy do eclipse manualmente 

echo -e ${RED}"ATENCAO: Configure o proxy no eclipse manualmente, apos trocar o usuario e senha!"${NOCOLOR}
echo -e ${RED}"ATENCAO: Configure as chaves ssh (Gitlab, Github, Azure) manualmente caso seja o primeiro uso do seu usuario neste Linux!"${NOCOLOR}
echo -e ${RED}"ATENCAO: Configure o proxy no postman manualmente, apos trocar o usuario e senha!"${NOCOLOR}
echo -e ""
