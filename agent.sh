#!/bin/bash

# Webshell Detection
WEBSHELL="<ossec_config>
  <localfile>
    <log_format>full_command</log_format>
    <command>ss -nputw | egrep '\"bash\"|\"csh\"|\"ksh\"|\"zsh\"'</command>
    <alias>webshell connections</alias>
    <frequency>10</frequency>
  </localfile>
</ossec_config>
"

echo $WEBSHELL >> /var/ossec/etc/ossec.conf

systemctl restart wazuh-agent

# Active Response
apt-get -y install iptables-persistent
cd ~/
git clone https://github.com/34006133/active_response
mv ~/active_response/script.py /var/ossec/active-response/bin
chmod 750 /var/ossec/active-response/bin/script.py
chown root:wazuh /var/ossec/active-response/bin/script.py

systemctl restart wazuh-agent

# Command Detection
