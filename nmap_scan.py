#!/usr/bin/env python
#This script scans the attacker's machine if no recent scans have been completed
#added by Josh Bauer <joshbauer3@gmail.com>

import sys
import subprocess
import sqlite3
from coret_config import *
import syslog
import socket

ip=sys.argv[1]

if DEBUG:
    syslog.syslog('DEBUGGING -- nmap_scan.py script started with ip = '+ip)
    
#check for recent scan of the given ip address
try:
  connection = sqlite3.connect('/opt/kojoney/kojoney.sqlite3')
  cursor = connection.cursor()
  # Only scan if we havne't done so recently (throttle)
  sql = """select count(id) from nmap_scans
            where time >  date('now','-5 minutes')
            and ip = ? order by time desc"""
  cursor.execute(sql, ip)
  num_recent_scans = cursor.fetchone()[0]
  cursor.close()
except Exception as err:
   errorstring =  "Transaction error in nmap_scan.py " , err
   syslog.syslog(syslog.LOG_ERR, str(errorstring))
   
if DEBUG:
    syslog.syslog('DEBUGGING -- nmap_scan.py checked database for recent scans, retval = '+str(num_recent_scans))
      
if num_recent_scans==0:
    
    if DEBUG:
        syslog.syslog('DEBUGGING -- nmap_scan.py calling nmap')
        
    #scan the attacker
    proc = subprocess.Popen("nmap -A -Pn -oX - %s" % ip, stdout=subprocess.PIPE, shell=True)
    (nmap_output, err) = proc.communicate()

    if nmap_output:
        #enter the scan into the database
        if DEBUG:
            syslog.syslog('DEBUGGING -- nmap_scan.py attempting to enter result into the database')
            
        try:
            cursor = connection.cursor()
            sql = """INSERT INTO nmap_scans (time, ip, ip_numeric, sensor_id, nmap_output)
                  VALUES (CURRENT_TIMESTAMP, ?, ?, ?, ?)"""
            cursor.execute(sql , (ip, socket.inet_aton(ip), SENSOR_ID, nmap_output))
            connection.commit() 
            cursor.close()
        except Exception as msg:
            errorstring = "Error inserting nmap data to the database.  ", msg
            syslog.syslog(syslog.LOG_ERR, str(errorstring))
    else:
        syslog.syslog("nmap error -- "+err)

if DEBUG:
    syslog.syslog('DEBUGGING -- nmap_scan.py end')