#!/usr/bin/env python
#
# This script scans the attacker's machine if no recent scans have been completed
# Called from login_loger in func.logger.py
#
# added by Josh Bauer <joshbauer3@gmail.com>

import subprocess
import syslog
import sys
import os.path


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
from conf.kojoney_config import DEBUG
from lib.kojoney_db import KojoneyDB

ip=sys.argv[1]


if DEBUG:
    syslog.syslog('DEBUGGING -- nmap_scan.py script started with ip = ' + ip)
    
#check for recent scan of the given ip address
try:
    num_recent_scans = KojoneyDB().num_recent_connects(ip)
except Exception as err:
    errorstring =  "Transaction error in nmap_scan.py " , err
    syslog.syslog(syslog.LOG_ERR, str(errorstring))
   
if DEBUG:
    syslog.syslog('DEBUGGING -- nmap_scan.py checked database for recent scans, retval = '+str(num_recent_scans))
      
if num_recent_scans==0:
    
    syslog.syslog('Kojoney2 nmap_scan.py calling nmap on ip ' + ip)
        
    #scan the attacker
    proc = subprocess.Popen("nmap -A -Pn -F -oX - %s" % ip, stdout=subprocess.PIPE, shell=True)
    (nmap_output, err) = proc.communicate()

    if nmap_output:
        #enter the scan into the database
        if DEBUG:
            syslog.syslog('DEBUGGING -- nmap_scan.py attempting to enter result into the database')
            
        try:
            KojoneyDB().log_nmap(ip, nmap_output)
        except Exception as msg:
            errorstring = "Error inserting nmap data to the database.  ", msg
            syslog.syslog(syslog.LOG_ERR, str(errorstring))
    else:
        syslog.syslog("nmap error -- "+err)

if DEBUG:
    syslog.syslog('DEBUGGING -- nmap_scan.py end')