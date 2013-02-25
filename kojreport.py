#! /bin/python

import MySQLdb

class Report:
  def __init__(self, host, user, password, database):
    try:
      self.conn = MySQLdb.connect(host=host,
                                  user=user,
                                  passwd=password,
                                  db=database,
                                  port=3306)
    except Exception as err:
      print "Error connecting to the database" , err
      return False

  def count_connects(self):
    'Show the number of connections since yesterday at midnight'
    try:
      cursor = self.conn.cursor()
      sql = 'select count(distinct(ip)) as session from koj_executed_commands '
      sql += 'where time > date_sub(curdate(), interval 1 day) order by time desc '
      cursor.execute(sql)
      retval = cursor.fetchone()[0]
      cursor.close()
      return retval
    except Exception as err:
      print "Transaction error in count_connects " , err
      return False

  def connects_from(self):
    'Show the IP address connections since yesterday at midnight'
    try:
      cursor = self.conn.cursor()
      sql = 'select distinct(ip) as session from koj_executed_commands '
      sql += 'where time > date_sub(curdate(), interval 1 day) order by time desc '
      cursor.execute(sql)
      retval = cursor.fetchall()
      cursor.close()
      return retval
    except Exception as err:
      print "Transaction error in count_connects " , err
      return False
  
  def get_commands(self, ip):
    'Show the commands that the ip address issued'
    try:
      cursor = self.conn.cursor()
      sql = 'select time, command, ip from koj_executed_commands '
      sql += 'where time > date_sub(curdate(), interval 1 day) '
      sql += ' and ip = %s order by time asc '
      cursor.execute(sql, ip)
      retval = cursor.fetchall()
      cursor.close()
      return retval
    except Exception as err:
      print "Transaction error in get_commands " , err
      return False
    
  def get_login_creds(self, ip, time):
    'Show last login for the ip before the time'
    try:
      cursor = self.conn.cursor()
      sql = 'select max(time), username, password from koj_login_attempts '
      sql += ' where ip_numeric = INET_ATON("%s") AND time < "%s"'
      cursor.execute(sql % (ip, time))
      retval = cursor.fetchone()
      cursor.close()
      return retval
    except Exception as err:
      print "Transaction error in get_login_creds " , err
      return False
    
  def get_file_downloads(self):
    'Show file downloads for the last day'
    try:
      cursor = self.conn.cursor()
      sql = 'select time, ip, url, md5sum, filetype from koj_downloads '
      sql += ' where time > date_sub(curdate(), interval 1 day) order by ip, time desc '
      cursor.execute(sql)
      retval = cursor.fetchall()
      cursor.close()
      return retval
    except Exception as err:
      print "Transaction error in get_file_downloads " , err
      return False
    

import urllib
import sys
import socket
import re
from coret_config import *
      
report = Report(DATABASE_HOST, DATABASE_USER, DATABASE_PASS, DATABASE_NAME)
print 'Kojoney2 activity in the last 24 hours.'
print
print 'Number of times a remote shell was opened:'
print '------------------------------------------'
print report.count_connects()
print
print 'IP addresses of connections:'
print '----------------------------'
ips = report.connects_from()
for addr in ips:
  print addr[0]
  ip = socket.gethostbyname(addr[0])
  response = urllib.urlopen('http://api.hostip.info/get_html.php?ip=' + ip + '&position=true').read()
  lines = response.split('\n')
  print '\t\t' + lines[0]
  print '\t\t' + lines[1]
print
print 'Executed commands by connection:'
print '--------------------------------'
for addr in ips:
  print addr[0]
  x = 1
  for cmds in report.get_commands(addr[0]):
    time = str(cmds[0])
    command = cmds[1]
    ip = cmds[2]
    if x == 1:
      creds = report.get_login_creds(ip, time)
      print '\t' + str(creds[1]) + ' : ' + str(creds[2])
      x = 0
    print '\t' + time + '\t' + command
print
print 'File downloads:'
print '--------------------------------'
for filedl in report.get_file_downloads():
  time = str(filedl[0])
  ip = str(filedl[1])
  url = str(filedl[2])
  md5sum = str(filedl[3])
  filetype = str(filedl[4])
  print ip + ' at ' + time + ':'
  print '\tURL:  ' + url
  print '\tMD5:  ' + md5sum
  print '\tType: ' + filetype
