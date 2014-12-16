#!/usr/bin/env python


from coret_config import *
import imp
import socket
import subprocess

try:
    imp.find_module('sqlite3')
    USE_DB = True
except ImportError:
    print "sqlite3 module wasn't found, skipping it."
    print "Maybe try:"
    print "pip install sqlite3"
    USE_DB = False
if USE_DB:
    import sqlite3

class HoneypotDB:

    _dberr = False

    # Singleton implementation
    def __call__(self):
        return self
    
    def __init__(self):
        if USE_DB:
            try:
                self.conn = sqlite3.connect('/opt/kojoney/kojoney.sqlite3')
            except Exception as err:
                print "ERROR: SQLite error in HoneypotDB.__init__() " , err
                self._dberr = True
        return None;
    
    def __del(self):
        self.connection.close()
    
    def check_recent(self, username):
        'Get recent login attempts with a username to limit valid passwords for a set time'
        #added by Josh Bauer <joshbauer3@gmail.com>
        if not self._dberr:
            try:
                cursor = self.conn.cursor()
                sql = """select password from login_attempts
                      where time > date('now','-1 day')
                      and username = ? order by time desc LIMIT 1"""
                cursor.execute(sql, (str(username),))
                retval = cursor.fetchone()
                cursor.close()
                return retval
            except Exception as err:
                print "ERROR: SQLite error in HoneypotDB.checkRecentAttempts() " , err
                return False
                    
    def log_command(self, command, ip):
        global WHITELIST
        #whitelist functionality added by Josh Bauer <joshbauer3@gmail.com>
        if ip in WHITELIST:
            print 'command database entry skipped due to whitelisted ip: '+ip
        elif not self._dberr:
            try:
                sql = """INSERT INTO executed_commands
                      (time, command, ip, ip_numeric, sensor_id)
                      VALUES
                      (CURRENT_TIMESTAMP, ?, ?, ?, ?)"""
                cursor = self.conn.cursor()
                cursor.execute(sql , (command, ip, socket.inet_aton(ip), SENSOR_ID))
                self.conn.commit()
                cursor.close()
            except sqlite3.Error as msg:
                print "ERROR: SQLite error in HoneypotDB.log_command()  ", msg
      
    def log_download(self,ip, url, filemd5, filename, filetype, SENSOR_ID):
        if not self._dberr:
            try:
                sql = """INSERT INTO downloads (time, ip, ip_numeric, url, md5sum, filename, filetype, sensor_id)
                          VALUES (CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?)"""
                cursor = self.conn.cursor()
                cursor.execute(sql , (ip, socket.inet_aton(ip), url, filemd5, filename, filetype, SENSOR_ID))
                self.conn.commit()
                cursor.close()
            except sqlite3.Error as msg:
                print "ERROR: SQLite error in HoneypotDB.log_download()  ", msg

    def log_login(self, ip, username, password):
        if not self._dberr:
            try:
                sql = """INSERT INTO login_attempts
                      (time, ip, ip_numeric, username, password, sensor_id)
                      VALUES
                      (CURRENT_TIMESTAMP, ?, ?, ?, ?, ?)"""
                cursor = self.conn.cursor()
                cursor.execute(sql , (ip, socket.inet_aton(ip), username, password, SENSOR_ID))
                self.conn.commit()
                cursor.close()
            except sqlite3.Error as msg:
                print "ERROR: SQLite error in HoneypotDB.log_login()  ", msg

    #add missing tables to the database
    #added by Josh Bauer <joshbauer3@gmail.com>
    def update_db(self):
        try:
            sql = """CREATE TABLE IF NOT EXISTS `login_attempts` (
                  `id` INTEGER PRIMARY KEY,
                  `time` TIMESTAMP,
                  `ip` VARCHAR(15),
                  `username` VARCHAR(16),
                  `password` VARCHAR(20),
                  `ip_numeric` INTEGER,
                  `sensor_id` INTEGER
                );

                CREATE TABLE IF NOT EXISTS `executed_commands` (
                  `id` INTEGER PRIMARY KEY,
                  `time` TIMESTAMP,
                  `ip` VARCHAR(15),
                  `command` VARCHAR(100),
                  `ip_numeric` INTEGER,
                  `sensor_id` INTEGER
                );

                CREATE TABLE IF NOT EXISTS `downloads` (
                  `id` INTEGER PRIMARY KEY,
                  `time` TIMESTAMP,
                  `ip` VARCHAR(15),
                  `ip_numeric` INTEGER,
                  `url` VARCHAR(100),
                  `md5sum` VARCHAR(32),
                  `filetype` VARCHAR(255),
                  `clamsig` TEXT,
                  `sensor_id` INTEGER
                  `file` LONGBLOB
                );

                -- nmap_scans table added by Josh Bauer <joshbauer3@gmail.com>
                CREATE TABLE IF NOT EXISTS `nmap_scans` (
                  `id` INTEGER PRIMARY KEY,
                  `time` TIMESTAMP,
                  `ip` VARCHAR(15),
                  `ip_numeric` INTEGER,
                  `sensor_id` INTEGER,
                  `nmap_output` TEXT
                );"""
            cursor = self.conn.cursor()
            cursor.executescript(sql)
            self.conn.commit()
            cursor.close()
            #subprocess.Popen('mysql -u %s --password=%s -h %s < create_tables.sql' % (DATABASE_USER, DATABASE_PASS, DATABASE_HOST) , stdout=subprocess.PIPE, shell=True)
        except sqlite3.Error as e:
            print "ERROR: SQLite error in HoneypotDB.update_db() ", e.args[0]