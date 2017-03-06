#!/usr/bin/python
# -*- coding: utf-8 -*-
#DNS reponse fuzz
#contact : lionel.prat9@gmail.com
from scapy.all import *
import sys
test = 1
def callback(pkt):
    global test
    dport=pkt.sprintf("%UDP.dport%")
    sport=pkt.sprintf("%UDP.sport%")
    ipsrc=pkt.sprintf("%IP.src%")
    ipdst=pkt.sprintf("%IP.dst%")
    if dport == "domain" and ipsrc == "127.0.0.1" and ipdst != "127.0.0.2":
        pkt.sprintf("%IP.src%:%UDP.sport%->%IP.dst%:%UDP.dport%")
        qdr=pkt[DNS].qd
        if pkt.haslayer(DNSQR):
	    qnamer=pkt.getlayer(DNSQR).qname
	    qtyper=pkt.getlayer(DNSQR).qtype
#            qtyper=2
	    classi=pkt.getlayer(DNSQR).qclass
            #print qnamer
        else:
	    print "Pas de QR...\n"
        if test == 1:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=4,ancount=1,nscount=0,arcount=0,qd=[DNSQR(qname=qnamer,qtype=qtyper,qclass=1)/DNSQR(qname=qnamer,qtype=qtyper,qclass=1)/DNSQR(qname=qnamer,qtype=qtyper,qclass=1)/DNSQR(qname=qnamer,qtype=qtyper,qclass=1)],an=DNSRR(rrname=qnamer,type=1,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 2:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=[DNSQR(qname=qnamer,qtype=qtyper,qclass=1)/DNSQR(qname=qnamer,qtype=qtyper,qclass=1)/DNSQR(qname=qnamer,qtype=qtyper,qclass=1)/DNSQR(qname=qnamer,qtype=qtyper,qclass=1)],an=DNSRR(rrname=qnamer,type=1,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 3:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=4,ancount=1,nscount=0,arcount=0,qd=[DNSQR(qname=qnamer,qtype=qtyper,qclass=1)/DNSQR(qname=qnamer+".com",qtype=qtyper,qclass=1)/DNSQR(qname=qnamer+".gov",qtype=qtyper,qclass=1)/DNSQR(qname=qnamer+".in",qtype=qtyper,qclass=1)],an=DNSRR(rrname=qnamer,type=1,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 4:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=4,ancount=1,nscount=0,arcount=0,qd=[DNSQR(qname=qnamer+".in",qtype=qtyper,qclass=1)/DNSQR(qname=qnamer+".com",qtype=qtyper,qclass=1)/DNSQR(qname=qnamer+".gov",qtype=qtyper,qclass=1)/DNSQR(qname=qnamer,qtype=qtyper,qclass=1)],an=DNSRR(rrname=qnamer,type=1,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 5:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=65535,ancount=1,nscount=0,arcount=0,qd=DNSQR(qname=qnamer,qtype=qtyper,qclass=1),an=DNSRR(rrname=qnamer,type=1,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 6:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=0,ancount=1,nscount=0,arcount=0,qd=DNSQR(qname=qnamer,qtype=qtyper,qclass=1),an=DNSRR(rrname=qnamer,type=1,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 7:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,an=DNSRR(rrname=qnamer,type=1,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 8:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=DNSQR(qname="www.rienavoir.fr",qtype=qtyper,qclass=1),an=DNSRR(rrname=qnamer,type=1,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 9:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=DNSQR(qname=qnamer+"\x00",qtype=qtyper,qclass=classi),an=DNSRR(rrname=qnamer,type=1,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 10:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=DNSQR(qname="\x00"+qnamer,qtype=qtyper,qclass=classi),an=DNSRR(rrname=qnamer,type=1,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 11:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=DNSQR(qname=qnamer+"\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f",qtype=qtyper,qclass=classi),an=DNSRR(rrname=qnamer,type=1,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 12:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=DNSQR(qname=qnamer+"\x08\x08\x08\x08\x08\x08\x08\x08\x08",qtype=qtyper,qclass=classi),an=DNSRR(rrname=qnamer,type=1,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 13:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=DNSQR(qname=qnamer+"\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a",qtype=qtyper,qclass=classi),an=DNSRR(rrname=qnamer,type=1,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 14:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=DNSQR(qname="\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f"+qnamer,qtype=qtyper,qclass=classi),an=DNSRR(rrname=qnamer,type=1,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 15:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=DNSQR(qname="\x08\x08\x08\x08\x08\x08\x08\x08\x08"+qnamer,qtype=qtyper,qclass=classi),an=DNSRR(rrname=qnamer,type=1,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 16:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=DNSQR(qname="\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a"+qnamer,qtype=qtyper,qclass=classi),an=DNSRR(rrname=qnamer,type=1,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 17:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=DNSQR(qname="."*1024,qtype=qtyper,qclass=classi),an=DNSRR(rrname=qnamer,type=1,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 18:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=DNSQR(qname="www.rien2voir.fr",qtype=qtyper,qclass=1),an=DNSRR(rrname="www.rien2voir.fr",type=1,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 19:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 20:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=0,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 21:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=-1234,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 22:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=655350,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 23:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=0,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 24:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=65535,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 25:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=[DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=10567,rdata="127.0.0.3")/DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=0,rdata="127.0.0.3")/DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=0,rdata="127.0.0.4")/DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=0,rdata="127.0.0.4")]))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 26:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer+"\x00",type=qtyper,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 27:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname="\x00"+qnamer,type=qtyper,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 28:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer+"\x08\x08\x08\x08\x08\x08\x08\x08",type=qtyper,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 29:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname="\x08\x08\x08\x08\x08\x08\x08\x08"+qnamer,type=qtyper,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 30:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer+"\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a",type=qtyper,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 31:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname="\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a"+qnamer,type=qtyper,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 32:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer+"\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f",type=qtyper,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 33:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname="\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f"+qnamer,type=qtyper,rclass=1,ttl=10567,rdata="127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 34:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 35:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=10567,rdata="127.0.0.3\x00")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 36:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=10567,rdata="\x00127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 37:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=10567,rdata="127.0.0.3\x08\x08\x08\x08\x08\x08\x08\x08")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 38:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=10567,rdata="\x08\x08\x08\x08\x08\x08\x08\x08127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 39:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=10567,rdata="\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 40:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=10567,rdata="127.0.0.3\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 41:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=10567,rdata="\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a127.0.0.3")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 42:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=10567,rdata="127.0.0.3\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a\x1a")))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=6
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 43:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=10567,rdata="127.0.0.3",rlen=-1234)))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 44:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=10567,rdata="127.0.0.3",rlen=0)))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 45:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=10567,rdata="127.0.0.3",rlen=65535)))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 46:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=10567,rdata="127.0.0.3",rlen=1)))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 47:
            send(IP(dst = pkt[IP].src,src = pkt[IP].dst)/UDP(sport = pkt[UDP].dport,dport = pkt[UDP].sport)/DNS(id= pkt[DNS].id,qr=1,opcode=0,ra=1,rcode=0,qdcount=1,ancount=1,nscount=0,arcount=0,qd=qdr,an=DNSRR(rrname=qnamer,type=qtyper,rclass=1,ttl=10567,rdata="127.0.0.3",rlen=512)))
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 48:
            
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 49:
            
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 50:
            
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 23:
            
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 24:
            
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 25:
            
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 19:
            
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 20:
            
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 21:
            
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 22:
            
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 23:
            
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 24:
            
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")
        if test == 25:
            
            print "qname = %s  - - qtype = %s - - test numero: %i" % (qnamer,qtyper,test)
            test+=1
            return pkt.sprintf("%IP.dst% : %UDP.dport% -> %IP.src% : %UDP.sport% >> DNS ID: %DNS.id%")            
#A partir de 18 phrase 2 mais dans phase1 pas de range65535

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'Syntaxe : /.py srv_DNS'
        exit(0)
    IPsrv = sys.argv[1]
    print "Lancer le script dig_fuzz2.py"
    try:
        sniff(filter="udp and src host " + IPsrv + " and dst port 53", prn=callback, store=0)
    except KeyboardInterrupt:
        exit(0)
