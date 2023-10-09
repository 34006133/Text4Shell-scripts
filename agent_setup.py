import subprocess

web_shell_command = """
<ossec_config>
  <localfile>
    <log_format>full_command</log_format>
    <command>ss -nputw | egrep '"sh"|"bash"|"csh"|"ksh"|"zsh"' | awk '{ print $5 "|" $6 }'</command>
    <alias>webshell connections</alias>
    <frequency>120</frequency>
  </localfile>
</ossec_config>
"""

command_monitoring_file = """
<ossec_config>
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
</ossec_config>
"""

audit_rule = """
-a exit,always -F arch=b64 -F euid=0 -S execve -k  audit-wazuh-c
-a exit,always -F arch=b32 -F euid=0 -S execve -k  audit-wazuh-c
"""

conf_path = "/var/ossec/etc/ossec.conf"
audit_rules_path = "/etc/audit/audit.rules"

def web_shell_setup():
  with open(conf_path, "a") as file:
    file.write(web_shell_command)

def command_monitoring_setup():
  subprocess.run("apt -y install auditd", shell=True)
  subprocess.run("systemctl start auditd", shell=True)
  subprocess.run("systemctl enable auditd", shell=True)
  with open(audit_rules_path, "a") as file:
    file.write(audit_rule)
  subprocess.run("auditctl -R /etc/audit/audit.rules", shell=True)
  subprocess.run("auditctl -l", shell=True)
  with open(conf_path, "a") as file:
    file.write(command_monitoring_file)

def active_response_setup():
  subprocess.run("apt-get install iptables-persistent", shell=True) 
  subprocess.run("git clone https://github.com/34006133/active_response", shell=True)
  subprocess.run("mv ~/active_response/script.py /var/ossec/active-response/bin", shell=True)
  subprocess.run("chmod 750 /var/ossec/active-response/bin/script.py", shell=True)
  subprocess.run("chown root:wazuh /var/ossec/active-response/bin/script.py", shell=True)

if __name__ == '__main__':
  web_shell_setup()
  command_monitoring_setup()
  active_response_setup()
  subprocess.run("sudo systemctl restart wazuh-agent", shell=True)
