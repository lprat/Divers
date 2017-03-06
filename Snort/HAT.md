#snort HAT
snort HAT
Creation de la HAT

/!\ Hogger ne fonctionne pas correctement, snort ignore tout ce qui n'est pas dans la HAT…

nmap
maj nmap-os-db
nmap -O -T4 -n -iL /root/scan-reseau -oN /root/resultat.scan
ou nmap -sV -T4 -iL  /root/scan-reseau -oN /root/resultat.scan
./hogger.pl -D nmap_dir/serv/ -c hostmap.csv -x host_attribute.xml
nmap_dir/serv contient les resultat de scan 
Compilation de snort avec option –enable-targetbased
attribute_table filename /path/to/host_attrib_table.xml


