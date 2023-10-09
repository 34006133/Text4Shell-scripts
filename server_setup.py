import subprocess

web_shell_decoder = """
<!-- Decoder for web shell network connection. -->
<decoder name="network-traffic-child">
  <parent>ossec</parent>
  <prematch offset="after_parent">^output: 'webshell connections':</prematch>
  <regex offset="after_prematch" type="pcre2">(\d+.\d+.\d+.\d+):(\d+)\|(\d+.\d+.\d+.\d+):(\d+)</regex>
  <order>local_ip, local_port, foreign_ip, foreign_port</order>
</decoder>
"""

web_shell_rule = """
<!-- This rule detects network connections from scripts. -->
<group name="linux, webshell,">
  <rule id="100510" level="12">
    <decoded_as>ossec</decoded_as>
    <match>ossec: output: 'webshell connections'</match>
    <description>[Network connection]: Script attempting network connection on source port: $(local_port) and destination port: $(foreign_port)</description>
    <mitre>
      <id>TA0011</id>
      <id>T1049</id>
      <id>T1505.003</id>
    </mitre>
  </rule>
</group>
"""

commands_to_monitor = """
ncat:red
nc:red
bash:red
sudo:red
curl:red
"""

command_monitoring_rule = """
<group name="audit">
  <rule id="100210" level="12">
      <if_sid>80792</if_sid>
  <list field="audit.command" lookup="match_key_value" check_value="red">etc/lists/commands</list>
    <description>Audit: Highly Suspicious Command executed: $(audit.exe)</description>
      <group>audit_command,</group>
  </rule>
</group>
"""

command_conf_list = """
<ossec_config>
  <ruleset>
    <list>etc/lists/commands</list>
  </ruleset>
</ossec_config>
"""

active_response_pair = """
<ossec_config>
  <command>
    <name>custom-response</name>
    <executable>script.py</executable>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>custom-response</command>
    <location>local</location>
    <rules_id>100510</rules_id>
  </active-response>
</ossec_config>
"""

conf_path = "/var/ossec/etc/ossec.conf"
decoder_path = "/var/ossec/etc/decoders/local_decoder.xml"
rule_path = "/var/ossec/etc/rules/webshell_rules.xml"
local_rule_path = "/var/ossec/etc/rules/local_rules.xml"
command_list_path = "/var/ossec/etc/lists/commands"

def web_shell_setup():
  with open(decoder_path, "a") as file:
    file.write(web_shell_decoder)
  with open(rule_path, "a") as file:
    file.write(web_shell_rule)
 
def command_monitoring_setup():
  subprocess.run(f"touch {command_list_path}", shell=True)
  with open(command_list_path, "a") as file:
    file.write(commands_to_monitor)
  with open(conf_path, "a") as file:
    file.write(command_conf_list)
  with open(local_rule_path, "a") as file:
    file.write(command_monitoring_rule)

def active_response_setup():
  with open(conf_path, "a") as file:
    file.write(active_response_pair)

if __name__ == '__main__':
  web_shell_setup()
  command_monitoring_setup()
  active_response_setup()
  subprocess.run("systemctl restart wazuh-manager", shell=True)
