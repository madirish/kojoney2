#!/usr/bin/env python
import sys
import MySQLdb
from coret_config import *
from xml.dom.minidom import *

#nmap_parser retrieves recent nmap scans from the data base and prints report information
#added by Josh Bauer <joshbauer3@gmail.com>
class nmap_parser:
    'Parses nmap xml output for reports'
    def __init__(self,ip):
        self.ip = ip
        self.scan = ''
        self.ports= ''
        if self.get_recent_scan():
            self.dom = parseString(self.scan)
            self.ports = self.get_ports()
        
    def get_recent_scan(self):
        'Gets the most recent scan from the last 24 hours from the database'
        try:
          connection = MySQLdb.connect(host=DATABASE_HOST, 
                                             user=DATABASE_USER, 
                                             passwd=DATABASE_PASS, 
                                             db=DATABASE_NAME)
          cursor = connection.cursor()
          sql = 'select nmap_output from nmap_scans '
          sql += 'where time > date_sub(curdate(), interval 1 day) '
          sql += 'and ip = %s order by time desc'
          cursor.execute(sql, self.ip)
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