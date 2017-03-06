#!/usr/bin/python
#
# License:
#
#    Copyright (c) 2003-2006 ossim.net
#    Copyright (c) 2007-2011 AlienVault
#    All rights reserved.
#
#    This package is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; version 2 dated June, 1991.
#    You may not use, modify or distribute this program under any other version
#    of the GNU General Public License.
#
#    This package is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this package; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
#    MA  02110-1301  USA
#
#
# On Debian GNU/Linux systems, the complete text of the GNU General
# Public License can be found in `/usr/share/common-licenses/GPL-2'.
#
# Otherwise you can read it here: http://www.gnu.org/licenses/gpl-2.0.txt
#

#
# GLOBAL IMPORTS
#
import time
import datetime
import re
import threading

#
# LOCAL IMPORTS
#
from OssimDB import OssimDB
from OssimConf import OssimConf
from Logger import Logger
from OCSAssetPlug import OCSAssetPlug
import Const
from Inventory import *

logger = Logger.logger
logocs = OCSAssetPlug.logger

#class OCSInventory():
class OCSInventory(threading.Thread):
    _interval = 3600
    
    def __init__(self):
        self._tmp_conf = OssimConf (Const.CONFIG_FILE)
        self.inv = Inventory()
        #Implement cache with timeout?????
        self.cache = []
        threading.Thread.__init__(self)

    def connectDB(self):
        self.db = OssimDB()
        self.db.connect (self._tmp_conf["ocs_host"],
                         self._tmp_conf["ocs_base"],
                         self._tmp_conf["ocs_user"],
                         self._tmp_conf["ocs_pass"])
    
    def closeDB(self):
        self.db.close()
        
    def run(self):
        OCSAssetPlug.set_verbose('info')
        OCSAssetPlug.add_file_handler('%s/OCSAsset.log' % Const.LOG_DIR)
        OCSAssetPlug.add_error_file_handler('%s/OCSAsset_error.log' % Const.LOG_DIR)
        OCSAssetPlug.remove_console_handler()
        while True:
            self.process()
            time.sleep(self._interval)
    
    def process(self):
        self.ossimHosts = self.inv.getListOfHosts()
        #print self.ossimHosts
        ocsHosts = self.getOCSHosts()
        for host in ocsHosts:
            ip = host['ipaddr']
            #Check if host is valid
            if self.inv.validateIp(ip):
                #Check if host exists
                if not ip in self.ossimHosts:
                    #Add host to ossim Database
                    logger.info("OCSAsset Adding IP in ASSET: %s" % (ip))
                    self.inv.insertHost(ip, None, host['name'], host['description'])
                    mac = self.getMACfromHost(host['id'], ip)
                    self.inv.insertProp(ip, "macAddress", "OCS", mac, None)
                    self.inv.insertProp(ip, "workgroup", "OCS", host['workgroup'], None)
                    self.inv.insertProp(ip, "department", "OCS", host['userid'], host['userdomain'])
                    self.inv.insertProp(ip, "operating-system", "OCS", host['osname'], None)
                    ocsSoft = self.getSoftware(host['id'])
                    for softw in ocsSoft:
                        self.inv.insertProp(ip, "software", "OCS", softw['name'], softw['version'])
                else:
                    #Host previously discovered
                    #OCS has the highest priority to replace properties
                    #protection DHCP client
                    dhcpprot = 0
                    props = self.inv.getProps(ip)
                    if self.inv.properties["macAddress"] not in props:
                        logger.info("OCSAsset Mac no save: %s" % (ip))
                        mac = self.getMACfromHost(host['id'], ip)
                        self.inv.insertProp(ip, "macAddress", "OCS", mac, None)
                    else:
                        #MAC change for ip then is possible other client acces by DHCP => not log change
                        logger.info("OCSAsset change mac ip: %s" % (ip))
                        mac = self.getMACfromHost(host['id'], ip)
                        MacIn = self.inv.getPropByHost(ip, "macAddress")
                        if MacIn[0]['value'] != mac:
                            #Mac change other client by dhcp?
                            self.inv.updateProp(ip, "macAddress", "OCS", mac, None) 
                            dhcpprot = 1 
                    if self.inv.properties["software"] not in props:
                        logger.info("OCSAsset Adding software in ASSET for IP %s" % (ip))
                        ocsSoft = self.getSoftware(host['id'])
                        for softw in ocsSoft:
                            self.inv.insertProp(ip, "software", "OCS", softw['name'], softw['version'])
                    else:
                        softIn = self.inv.getPropByHost(ip, "software")
                        ocsSoft = self.getSoftware(host['id'])
                        nsoft = 0
                        for softw in ocsSoft:
                            for softwIn in softIn:
                                if softw['name'] == softwIn['value'] and softw['version'] == softwIn['extra']:
                                    #soft present
                                    nsoft = 1
                            if nsoft == 0:
                                #insert soft and new event
                                self.inv.insertProp(ip, "software", "OCS", softw['name'], softw['version'])
                                if dhcpprot == 1:
                                    logocs.info("%s [OCSAsset] -- Info -- SoftWare add IP:%s SoftName:%s SoftVersion:%s" % (datetime.datetime.now().isoformat(' '),ip,softw['name'], softw['version']))
                            else:
                                nsoft = 0
                        for softwIn in softIn:
                            for softw in ocsSoft:
                                if softw['name'] == softwIn['value'] and softw['version'] == softwIn['extra']:
                                    #soft present
                                    nsoft = 1
                            if nsoft == 0:
                                #delete - old soft and event
                                self.inv.deleteProp(ip, "software", "OCS", softw['name'], softw['version'])
                                if dhcpprot == 1:
                                    logocs.info("%s [OCSAsset] -- Info -- SoftWare delete IP:%s SoftName:%s SoftVersion:%s" % (datetime.datetime.now().isoformat(' '),ip,softw['name'], softw['version']))
                            else:
                                nsoft = 0
                    if self.inv.properties["workgroup"] not in props:        
                        self.inv.insertProp(ip, "workgroup", "OCS", host['workgroup'], None)
                    else:
                        self.inv.updateProp(ip, "workgroup", "OCS", host['workgroup'], None)
                    
                    #OS
                    cpe = self.inv.generateCPE(host['osname'], host['osversion'], host['oscomments'])
                    if not cpe:
                        cpe = host['oscomments']    
                    if self.inv.properties["operating-system"] not in props:
                        self.inv.insertProp(ip, "operating-system", "OCS", host['osname'], cpe)
                    else:
                        OsIn = self.inv.getPropByHost(ip, "operating-system")
                        if OsIn:
                            if OsIn[0]['value'] != host['osname'] and OsIn[0]['extra'] != cpe:
                                self.inv.updateProp(ip, "operating-system", "OCS", host['osname'], cpe)
                                if dhcpprot == 1:
                                    logocs.info("%s [OCSAsset] -- Info -- OS Update IP:%s OSname:%s OSversion:%s" % (datetime.datetime.now().isoformat(' '),ip,host['osname'],cpe))

                    #Username
                    if self.inv.properties["department"] not in props:
                        self.inv.insertProp(ip, "department", "OCS", host['userid'], host['userdomain'])
                    else:
                        UserIn = self.inv.getPropByHost(ip, "department")
                        if UserIn[0]['value'] != host['userid'] and UserIn[0]['extra'] != host['userdomain']:
                            #Mac change other client by dhcp?
                            self.inv.updateProp(ip, "department", "OCS", host['userid'], host['userdomain'])
                            if dhcpprot == 1:
                                logocs.info("%s [OCSAsset] -- Info -- UserName Update IP:%s UserName:%s UserDomain:%s" % (datetime.datetime.now().isoformat(' '),ip,host['userid'],host['userdomain'])) 

    def getOCSHosts(self):
        self.connectDB()
        #sql = "select id,name,osname,osversion,ipaddr,workgroup,description,oscomments,userid,userdomain from ocsweb.hardware;"
        sql = "SELECT * FROM (SELECT id,name,osname,osversion,ipaddr,workgroup,description,oscomments,userid,userdomain,lastdate FROM hardware ORDER BY lastdate DESC) as t GROUP BY t.ipaddr;"
        data = self.db.exec_query(sql)
        self.closeDB()
        return data
    
    def getSoftware(self, id):
        self.connectDB()
        sql = "select name,version from ocsweb.softwares where HARDWARE_ID = '%d';" % (id)
        data = self.db.exec_query(sql)
        self.closeDB()
        return data
        
    def getMACfromHost(self, id, ip):
        self.connectDB()
        sql = "select MACADDR from ocsweb.networks where HARDWARE_ID = %d and IPADDRESS = '%s';" % (id, ip)
        data = self.db.exec_query(sql)
        #logger.info("OCSAsset resu: %d" % (data))
        self.closeDB()
        if data:
            return data[0]['MACADDR']
        
if __name__ == '__main__':
    ocs = OCSInventory()
    ocs.start()
