#snort oink
Adapter les SIGs auto par oink

Adapter les sigs aux services/protocoles/ports autorisés (éviter trop de DROP/charge) /!\ penser a rajouter

$FILE_DATA_PORTS

grep -i "4" ../classification.config | awk -F " " '{print $3}' | awk -F "," '{print $1}'
4:tcp-connection
3:not-suspicious,unknown,string-detect,network-scan,protocol-command-decode,misc-activity,icmp-event
2:bad-unknown,attempted-recon,successful-recon-limited,successful-recon-largescale,attempted-dos,successful-dos,rpc-portmap-decode,suspicious-filename-detect,suspicious-login,system-call-detect,unusual-client-port-connection,denial-of-service,non-standard-protocol,web-application-activity,misc-attack,default-login-attempt,sdf
1:attempted-user,unsuccessful-user,successful-user,attempted-admin,successful-admin,shellcode-detect,trojan-activity,web-application-attack,inappropriate-content,policy-violation

#laisser les alertes que pour les ports réels ...Il faut bien sur modifié car c'est pas l’opérationnel!
modifysid * "^alert (.*tcp\s+(\$EXTERNAL_NET|any)\s+.*\s*\-\>\s*(any|\$SSH_SERVERS|\$HTTP_SERVERS|\$SMTP_SERVERS|\$DNS_SERVERS|\$HOME_NET)\s+((?!21\s+|80\s+|443\s+|any\s+|\$HTTP_PORTS\s+|\$SHELLCODE_PORTS\s+|\$SSH_PORTS\s+|\$FTP_PORTS\s+|(\d*:\d*)).+))" | "#DEL#alert ${1}"
modifysid * "^alert (.*tcp\s+(any|\$SSH_SERVERS|\$HTTP_SERVERS|\$SMTP_SERVERS|\$DNS_SERVERS|\$HOME_NET)\s+((?!21\s+|80\s+|443\s+|any\s+|\$HTTP_PORTS\s+|\$SHELLCODE_PORTS\s+|\$SSH_PORTS\s+|\$FTP_PORTS\s+|\$SIP_PORTS\s+|(\d*:\d*)).+))\s+\-\>\s+(\$EXTERNAL_NET|any)\s+.*" | "#DEL#alert ${1}"
modifysid * "^alert (.*tcp\s+(any|\$SSH_SERVERS|\$HTTP_SERVERS|\$SMTP_SERVERS|\$DNS_SERVERS|\$HOME_NET)\s+.*\s*\-\>\s*(\$EXTERNAL_NET|any)\s+((?!21\s+|80\s+|443\s+|any\s+|\$HTTP_PORTS\s+|\$SHELLCODE_PORTS\s+|\$SSH_PORTS\s+|\$FTP_PORTS\s+|\$SIP_PORTS\s+|(\d*:\d*)).+))" | "#DEL#alert ${1}"
modifysid * "^alert (.*tcp\s+(\$EXTERNAL_NET|any)\s+((?!21\s+|80\s+|443\s+|any\s+|\$HTTP_PORTS\s+|\$SHELLCODE_PORTS\s+|\$FTP_PORTS\s+|(\d*:\d*)).+))\s+\-\>\s+(any|\$SSH_SERVERS|\$HTTP_SERVERS|\$HOME_NET)\s+.*" | "#DEL#alert ${1}"
#Virer niveau 3 & 4
modifysid * "^alert (.*classtype\:\s*tcp-connection|.*classtype\:\s*not-suspicious|.*classtype\:\s*unknown|.*classtype\:\s*string-detect|.*classtype\:\s*network-scan|.*classtype\:\s*protocol-command-decode|.*classtype\:\s*misc-activity|.*classtype\:\s*icmp-event)" | "#RS#alert ${1}"
#Virer les vieilles failles absentes du reseau...
modifysid * "^alert (.*reference:cve,199?)" | "#L#alert ${1}"
modifysid * "^alert (.*reference:cve,200[0-7])" | "#L#alert ${1}"


