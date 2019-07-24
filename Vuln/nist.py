#!/usr/bin/python
# -*- coding: utf-8 -*-
# Lionel PRAT lionel.prat9@gmail.com (2019)
# Send New NIST CVE with score CVSS > 7 in your mail

import smtplib
import sys
import json
import re
import time
import os
import socket
import shutil
import urllib2
import gzip
from json2html import *
from StringIO import StringIO
from datetime import datetime
from string import Template
from datetime import datetime
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
from email.header import Header

def sendmail(cve,cvssv3,cvssv3d,description,full):
  user = 'you@domain.fr'
  password = ''
  sent_from = user
  to = ['destination@domain.fr']
  subject = Header(u'[CVE][NIST][New]'+cve.encode('UTF-8')+u' score v3 ['+str(cvssv3).encode('UTF-8')+u'] published by NIST', 'utf-8')
  fullh=json2html.convert(json = full)
  urlx='https://nvd.nist.gov/vuln/detail/'+cve
  html='<!DOCTYPE html><html xmlns="http://www.w3.org/1999/xhtml" lang="" xml:lang=""><head><meta charset="utf-8" /><title>New CVE NIST</title></head><body><h1>New '+cve+' score v3 '+str(cvssv3)+'</h1><p>Detail score cvss v3: '+cvssv3d+'</p><p>Description: '+description+'</p><p>Link: <a href=\"'+urlx+'\">'+urlx+'</a></p><h2>JSON extract</h2>'+fullh+'</body></html>'
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
    print "Error to send mail!!!"

data={}
cvex={}
if os.path.isfile("sf-cve.json"):
  with open('sf-cve.json') as f:
    try:
      data = json.load(f)
    except:
      print "Error to load sf-cve.json!!!"
      sys.exit()
else:
  print "Error to load sf-cve.json!!!"
  sys.exit()
url= "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.gz"
#proxy = urllib2.ProxyHandler( {"https":"http://proxy:3123/"} )
#opener = urllib2.build_opener(proxy)
#urllib2.install_opener(opener)
response = urllib2.urlopen(url)
filegz = response.read()
gzip_file_handle = gzip.GzipFile(fileobj=StringIO(filegz)).read()
text_file = open("Output.txt", "w")
text_file.write(gzip_file_handle)
text_file.close()
if os.path.isfile("Output.txt"):
  with open('Output.txt') as f:
    try:
      cvex = json.load(f)
    except:
      print "Error to load sf-cve.json!!!"
      sys.exit()
now=datetime.now()
year=time.strftime("%Y")
if not 'CVE_data_timestamp' in data:
  data['CVE_data_timestamp']=""
if cvex['CVE_data_timestamp'] != data['CVE_data_timestamp']:
  data['CVE_data_timestamp']=cvex['CVE_data_timestamp']
  for cvez in cvex['CVE_Items']:
    try:
      cveid=cvez['cve']['CVE_data_meta']['ID']
      cvss3=cvez['impact']['baseMetricV3']['cvssV3']['baseScore']
      cvss3d=cvez['impact']['baseMetricV3']['cvssV3']['vectorString']
      description=cvez['cve']['description']['description_data'][0]['value']
      if str(year) in str(cveid) and str(cveid) not in data and cvss3 >= 7:
        #add
        data[str(cveid)]=str(now)
#        print "Cve:"+str(cveid)
#        print "CVSS: "+str(cvss3)+"("+cvss3d+")"
#        print "description:"+description
        sendmail(cveid,cvss3,cvss3d,description,cvez)
    except Exception as inst:
#      print "Error:"+str(inst)
#      print "CVE DATA:"+str(cvez)
      continue
  if os.path.isfile("sf-cve.json"):
    shutil.move('sf-cve.json','sf-cve.json.old')
    with open('sf-cve.json', 'w+') as file:
      try:
        file.write(json.dumps(data))
      except:
        if os.path.isfile("sf-cve.json.old"):
          shutil.move('sf-cve.json.old','sf-cve.json')
