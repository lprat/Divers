#!/usr/bin/python
# -*- coding: utf-8 -*-
# Lionel PRAT lionel.prat9@gmail.com (2019)
# Send mail on new alert of ANSSI - use crontab for run

import feedparser
import smtplib
import sys
import json
import re
import time
import os
import socket
import shutil
import urllib2
from string import Template
from datetime import datetime
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
from email.header import Header

def sendmail(title,published,summary,link,date):
  user = 'you@domain.fr'  
  password = ''
  sent_from = user
  to = ['you@domain.fr']
  subject = Header('[ANSSI][Alerte] Vulnerabilité type CVE publié par ANSSI le '+date, 'utf-8')
  with open('cve.html', 'r') as content_file:
    content = content_file.read()
  html = Template(content)
  datax="<p>"+title.encode('utf8')+"</p><p>Date de publication: "+published.encode('utf8')+"</p><p>Date de publication par ANSSI: "+date+"</p><p>Description: "+summary.encode('utf8')+"</p><p>Lien URL: "+link.encode('utf8')+"</p>"
  html=html.substitute(cve=link.encode('utf8'), datatech=datax)
  codage = 'utf-8'
  msg = MIMEMultipart()
  msg['From'] = user
  msg['To'] = ", ".join(to)
  msg['Subject'] = subject
  msg['Charset'] = codage
  typetexte = 'plain'
  typehtml = 'html'
  msg.attach(MIMEText(html, typehtml, codage))
  msg['Content-Type'] = "text/html; charset=utf-8"
  try:  
    server = smtplib.SMTP('smtp.domain.fr', 25)
    server.ehlo()
    #server.login(user, password)
    server.sendmail(sent_from, to, msg.as_string())
    server.close()
    print 'Email sent!'
  except:  
    print "Error send mail!!!"

data={}        
if os.path.isfile("anssi-cve.json"):
  with open('anssi-cve.json') as f:
    try:
      data = json.load(f)
    except:
      print "Error to load anssi-cve.json!!!"
      sys.exit()
else:
  print "Error to load anssi-cve.json!!!"
  sys.exit()
url= "https://www.cert.ssi.gouv.fr/alerte/feed/"
#proxy = urllib2.ProxyHandler( {"https":"http://proxy:3123/"} )
feed = feedparser.parse(url,handlers = [proxy])
for post in feed.entries:
  date = "(%d/%02d/%02d)" % (post.published_parsed.tm_year,\
    post.published_parsed.tm_mon, \
    post.published_parsed.tm_mday)
#  print("post date: " + date)
#  print("post title: " + post.title)
#  print("post link: " + post.link)
#  print("post summary: " + post.summary)
#  print("post published: " + post.published)
  if not post.link in data:
#    print 'Send Mail:'+post.link
    data[post.link]=date
    sendmail(post.title,post.published,post.summary,post.link,date)
  if os.path.isfile("anssi-cve.json"):
    shutil.move('anssi-cve.json','anssi-cve.json.old')
    with open('anssi-cve.json', 'w+') as file:
      try:
        file.write(json.dumps(data))
      except:
        if os.path.isfile("anssi-cve.json.old"):
          shutil.move('anssi-cve.json.old','anssi-cve.json')
