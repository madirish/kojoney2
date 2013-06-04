#!/usr/bin/env python
#This script scans the attacker's machine if no recent scans have been completed
#added by Josh Bauer <joshbauer3@gmail.com>
import sys
import subprocess
import MySQLdb
from coret_config import *
import syslog

ip=sys.argv[1]

if DEBUG:
    syslog.syslog('DEBUGGING -- nmap_scan.py script started with ip = '+ip)
    
#check for recent scan of the given ip address
try:
  connection = MySQLdb.connect(host=DATABASE_HOST, 
                                     user=DATABASE_USER, 
                                     passwd=DATABASE_PASS, 
                                     db=DATABASE_NAME)
  cursor = connection.cursor()
  sql = 'select count(id) from nmap_scans '
  sql += 'where time > date_sub(now(), interval 1 hour) '
  sql += 'and ip = %s order by time desc'
  cursor.execute(sql, ip)
  retval = cursor.fetchone()[0]
  cursor.close()
except Exception as err:
   errorstring =  "Transaction error in nmap_scan.py " , err
   syslog.syslog(syslog.LOG_ERR, str(errorstring))
   
if DEBUG:
    syslog.syslog('DEBUGGING -- nmap_scan.py checked database for recent scans, retval = '+str(retval)) 
      
if retval==0:
    
    if DEBUG:
        syslog.syslog('DEBUGGING -- nmap_scan.py calling nmap')
        
    #scan the attacker
    proc = subprocess.Popen("nmap -A -Pn -oX - %s" % ip, stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()

    if out:
        #enter the scan into the database
        if DEBUG:
            syslog.syslog('DEBUGGING -- nmap_scan.py attempting to enter result into the database')
            
        try:
            connection = MySQLdb.connect(host=DATABASE_HOST, 
                                         user=DATABASE_USER, 
                                         passwd=DATABASE_PASS, 
                                         db=DATABASE_NAME)
            cursor = connection.cursor()
            sql = "INSERT INTO nmap_scans SET "
            sql += " time=CURRENT_TIMESTAMP(), "
            sql += " ip=%s, "
            sql += " ip_numeric=INET_ATON(%s),"
            sql += " sensor_id=%s, "
            sql += " nmap_output=%s"
            cursor.execute(sql , (ip, ip, SENSOR_ID, out))
            connection.commit() 
            cursor.close()
        except Exception as msg:
            errorstring = "Error inserting nmap data to the database.  ", msg
            syslog.syslog(syslog.LOG_ERR, str(errorstring))
    else:
        syslog.syslog("nmap error -- "+err)

if DEBUG:
    syslog.syslog('DEBUGGING -- nmap_scan.py end')