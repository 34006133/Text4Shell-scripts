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
apt -y install auditd
systemctl start auditd
systemctl enable auditd

echo "-a exit,always -F arch=b64 -F euid=0 -S execve -k  audit-wazuh-c" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b32 -F euid=0 -S execve -k  audit-wazuh-c" >> /etc/audit/audit.rules

auditctl -R /etc/audit/audit.rules
auditctl -l

COMMANDS="<ossec_config>
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
</ossec_config>
"

echo $COMMANDS >> /var/ossec/etc/ossec.conf

systemctl restart wazuh-agent
