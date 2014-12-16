#!/usr/bin/env python
import syslog
import sqlite3
from xml.dom.minidom import *

# nmap_parser retrieves recent nmap scans from the data base and prints report information
# added by Josh Bauer <joshbauer3@gmail.com>
class NmapParser:
    'Parses nmap xml output for reports'
    def __init__(self,ip):
        self.ip = ip
        self.scan = ''
        self.ports= ''
        self.conn = sqlite3.connect('/opt/kojoney/kojoney.sqlite3')
        if self.get_scans_since_yetserday():
            self.dom = parseString(self.scan)
            self.ports = self.get_ports()
        
    def get_scans_since_yetserday(self):
        'Gets the most recent scan from the last 24 hours from the database'
        try:
          cursor = self.conn.cursor()
          sql = """select nmap_output from nmap_scans
                  where time > date('now','-1 day')
                  and ip = ? order by time desc"""
          cursor.execute(sql, (str(self.ip),))
          retval = cursor.fetchone()          
          cursor.close()
          if retval:
              self.scan=retval[0]
              return True
          else:
              return False
        except Exception as err:
           errorstring =  "Transaction error in nmap_parser.py " , err
           syslog.syslog(syslog.LOG_ERR, str(errorstring))
           return False

    def get_ports(self):
        'Parses the ports from the scan'
        return self.dom.getElementsByTagName('port')
    
    def report(self):
        'Prints information about the scan for the report'
        print self.ip
        if len(self.ports)>0:
            for port in self.ports:
                print '\tport: '+port.getAttribute('portid')
                for child in port.childNodes:
                    if child.nodeName == 'state':
                        print '\t\tstate: '+child.getAttribute('state')
                    elif child.nodeName == 'service':
                        print '\t\tservice: '+child.getAttribute('name')
                        print '\t\tproduct: '+child.getAttribute('product')
                        print '\t\tversion: '+child.getAttribute('version')
        else:
            print '\tNo port information'