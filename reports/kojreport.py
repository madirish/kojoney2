#! /bin/python

import sqlite3
import syslog
import socket
import os
from nmap_parser import nmap_parser


class Report:
  def __init__(self):
    try:
      self.conn = sqlite3.connect('/opt/kojoney/kojoney.sqlite3')
    except Exception as err:
      errorstring = "Kojoney2: kojreport - Error connecting to the database", err
      syslog.syslog(syslog.LOG_ERR, errorstring)
      return False

  def count_connects(self):
    'Show the number of connections since yesterday at midnight'
    try:
      cursor = self.conn.cursor()
      sql = """select count(distinct(ip)) as session from executed_commands
            where time > date('now','-1 day') order by time desc """
      cursor.execute(sql)
      retval = cursor.fetchone()[0]
      cursor.close()
      return retval
    except Exception as err:
      errorstring = "Kojoney2: kojreport - Transaction error in count_connects ", err
      syslog.syslog(syslog.LOG_ERR, str(errorstring))
      return False

  def connects_from(self):
    'Show the IP address connections since yesterday at midnight'
    try:
      cursor = self.conn.cursor()
      sql = """select distinct(ip) as session from executed_commands
            where time > date('now','-1 day') order by time desc """
      cursor.execute(sql)
      retval = cursor.fetchall()
      cursor.close()
      return retval
    except Exception as err:
      errorstring = "Transaction error in count_connects ", err
      syslog.syslog(syslog.LOG_ERR, str(errorstring))
      return False

  def get_commands(self, ip):
    'Show the commands that the ip address issued'
    try:
      cursor = self.conn.cursor()
      sql = """select time, command, ip from executed_commands '
          where time > date('now','-1 day')
          and ip = ? order by time asc """
      cursor.execute(sql, (str(ip),))
      retval = cursor.fetchall()
      cursor.close()
      return retval
    except Exception as err:
      errorstring = "Kojoney2: kojreport - Transaction error in get_commands ", err
      syslog.syslog(syslog.LOG_ERR, str(errorstring))
      return False

  def get_login_creds(self, ip, time):
    'Show last login for the ip before the time'
    try:
      cursor = self.conn.cursor()
      sql = """select username, password from login_attempts
            where ip_numeric = ? AND time < ? order by time desc"""
      cursor.execute(sql, (socket.inet_aton(ip), time))
      retval = cursor.fetchone()
      cursor.close()
      return retval
    except Exception as err:
      errorstring = "Kojoney2: kojreport - Transaction error in get_login_creds ", err
      syslog.syslog(syslog.LOG_ERR, str(errorstring))
      return False

  def get_file_downloads(self):
    'Show file downloads for the last day'
    try:
      cursor = self.conn.cursor()
      sql = """select time, ip, url, md5sum, filetype from downloads
            where time > date('now','-1 day') order by ip, time desc"""
      cursor.execute(sql)
      retval = cursor.fetchall()
      cursor.close()
      return retval
    except Exception as err:
      errorstring = "Kojoney2: kojreport - Transaction error in get_file_downloads ", err
      syslog.syslog(syslog.LOG_ERR, str(errorstring))
      return False

  def count_attempts(self):
    'Show the number of successful login attempts since yesterday at midnight'
    try:
      cursor = self.conn.cursor()
      sql = """select count(id) from login_attempts
              where time > date('now','-1 day')"""
      cursor.execute(sql)
      retval = cursor.fetchone()[0]
      cursor.close()
      return retval
    except Exception as err:
      errorstring = "Kojoney2: kojreport - Transaction error in count_attempts ", err
      syslog.syslog(syslog.LOG_ERR, str(errorstring))
      return False

  def attempts_from(self):
    'Show the ip addresses of successful login attempts since yesterday at midnight'
    try:
      cursor = self.conn.cursor()
      sql = """select distinct(ip) from login_attempts
              where time > date('now','-1 day')"""
      cursor.execute(sql)
      retval = cursor.fetchall()
      cursor.close()
      return retval
    except Exception as err:
      errorstring = "Kojoney2: kojreport - Transaction error in attempts_from ", err
      syslog.syslog(syslog.LOG_ERR, str(errorstring))
      return False

  def get_attempts(self, ip):
    'Show the successful login attempts by the ip address issued since yesterday at midnight'
    try:
      print "Looking for connects with IP " + ip
      # total succeful attempts by ip
      cursor = self.conn.cursor()
      sql = """select count(id) from login_attempts
            where time > date('now','-1 day')
            and ip = ?"""
      cursor.execute(sql, (str(ip),))
      total = cursor.fetchone()
      #succesful attemps with unique username by ip
      sql = """select count(distinct(username)) from login_attempts
              where time > date('now','-1 day')
              and ip = ?"""
      cursor.execute(sql, (str(ip),))
      unique = cursor.fetchone()
      cursor.close()
      return (total[0], unique[0])
    except Exception as err:
      errorstring = "Kojoney2: kojreport - Transaction error in get_attempts ", err
      syslog.syslog(syslog.LOG_ERR, str(errorstring))
      return False


import urllib
import socket
from coret_config import *

report = Report()
print 'Kojoney2 activity in the last 24 hours.'
print
print 'Number of times a remote shell was opened:'
print '------------------------------------------'
print report.count_connects()
print
print 'IP addresses of connections:'
print '----------------------------'
ips = report.connects_from()
if ips is not False:
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
if ips is not False:
  for addr in ips:
    print addr[0]
    x = 1
    commands = report.get_commands(addr[0])
    if commands is not False:
      for cmds in commands:
        time = str(cmds[0])
        command = cmds[1]
        ip = cmds[2]
        if x == 1:
          creds = report.get_login_creds(ip, time)
          if creds is not False:
            print '\t' + str(creds[0]) + ' : ' + str(creds[1])
          x = 0
        print '\t' + time + '\t' + command
print
print 'File downloads:'
print '--------------------------------'
downloads = report.get_file_downloads()
if downloads is not False:
  for filedl in downloads:
    time = str(filedl[0])
    ip = str(filedl[1])
    url = str(filedl[2])
    md5sum = str(filedl[3])
    filetype = str(filedl[4])
    print ip + ' at ' + time + ':'
    print '\tURL:  ' + url
    print '\tMD5:  ' + md5sum
    print '\tType: ' + filetype
print
print 'Number of successful login attempts:'
print '------------------------------------'
print report.count_attempts()
print
print 'IP addresses of successful login attempts'
print '-----------------------------------------'
ips = report.attempts_from()
if ips is not False:
  for addr in ips:
    print addr[0]
    ip = socket.gethostbyname(addr[0])
    response = urllib.urlopen('http://api.hostip.info/get_html.php?ip=' + ip + '&position=true').read()
    lines = response.split('\n')
    print '\t\t' + lines[0]
    print '\t\t' + lines[1]
print
print 'Attempts by IP address:'
print '--------------------------------'
if ips is not False:
  for addr in ips:
    print addr[0]
    total, unique = report.get_attempts(addr[0])
    output = ''
    if total == 1:
      output += '\t' + str(total) + ' login with '
    else:
      output += '\t' + str(total) + ' logins with '
    if unique == 1:
      output += str(unique) + ' unique username'
    else:
      output += str(unique) + ' unique usernames'
    print output
print
print 'Attacker Scans by IP address:'
print '--------------------------------'
if ips is not False:
  for addr in ips:
    scan = nmap_parser(addr[0])
    scan.report()
