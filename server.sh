#!/bin/bash

# Webshell Detection
WEBSHELL_DECODER="<!-- Decoder for web shell network connection. -->
<decoder name=\"network-traffic-child\">
  <parent>ossec</parent>
  <prematch offset=\"after_parent\">^output: 'webshell connections':</prematch>
  <regex offset=\"after_prematch\" type=\"pcre2\">(\d+.\d+.\d+.\d+):(\d+)\|(\d+.\d+.\d+.\d+):(\d+)</regex>
  <order>local_ip, local_port, foreign_ip, foreign_port</order>
</decoder>
"
echo $WEBSHELL_DECODER >> /var/ossec/etc/decoders/local_decoder.xml

WEBSHELL_RULE="<!-- This rule detects network connections from scripts. -->
<group name=\"linux, webshell,\">
  <rule id=\"100510\" level=\"12\">
    <decoded_as>ossec</decoded_as>
    <match>ossec: output: 'webshell connections'</match>
    <description>[Network connection]: Script attempting network connection on source port: \$(local_port) and destination port: \$(foreign_port)</description>
    <mitre>
      <id>TA0011</id>
      <id>T1049</id>
      <id>T1505.003</id>
    </mitre>
  </rule>
</group>
"
echo $WEBSHELL_RULE >> /var/ossec/etc/rules/webshell_rules.xml

systemctl restart wazuh-manager


# Active Response
ACTIVE_RESPONSE_CONF="<ossec_config>
  <command>
    <name>custom-response</name>
    <executable>script.py</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>custom-response</command>
    <location>local</location>
    <rules_id>100510</rules_id>
  </active-response>
</ossec_config>
"
echo $ACTIVE_RESPONSE_CONF >> /var/ossec/etc/ossec.conf

systemctl restart wazuh-manager

# Command Detection
CDB_LIST="ncat:red
\nbash:red
\ncurl:red
\nnc:red
"
echo $CDB_LIST >> /var/ossec/etc/lists/sus-commands

RULESET="<ossec_config>
  <ruleset>
    <list>etc/lists/sus-commands</list>
  </ruleset>
</ossec_config>
"
echo $RULESET >> /var/ossec/etc/ossec.conf

COMMAND_RULE="<group name=\"audit\">
  <rule id="100210" level="12">
      <if_sid>80792</if_sid>
  <list field=\"audit.command\" lookup=\"match_key_value\" check_value=\"red\">etc/lists/sus-commands</list>
    <description>Audit: Highly Suspicious Command executed: \$(audit.exe)</description>
      <group>audit_command,</group>
  </rule>
</group>
"
echo $COMMAND_RULE >> /var/ossec/etc/rules/local_rules.xml

systemctl restart wazuh-manager
