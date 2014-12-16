#!/usr/bin/env python


from coret_config import *
import imp

try:
    imp.find_module('MySQLdb')
    USE_DB = True
except ImportError:
    print "MySQLdb module wasn't found, skipping it."
    print "Maybe try:"
    print "pip install mysqldb"
    USE_DB = False
if USE_DB:
    import MySQLdb

class HoneypotDB:
    
    def __init__(self):
        self.dberr = False
        if USE_DB:
            try:
              self.connection = MySQLdb.connect(host=DATABASE_HOST,
                                                 user=DATABASE_USER,
                                                 passwd=DATABASE_PASS,
                                                 db=DATABASE_NAME)
            except Exception as err:
                print "Error connecting to the database."
                self.dberr = True
        return None;
    
    def __del(self):
        self.connection.close()
    
    def check_recent(self, username):
        'Get recent login attempts with a username to limit valid passwords for a set time'
        #added by Josh Bauer <joshbauer3@gmail.com>
        if not self.dberr:
            try:
              cursor = self.connection.cursor()
              sql = 'select password from login_attempts '
              sql += 'where time > date_sub(now(), interval 1 hour) '
              sql += 'and username = %s order by time desc'
              cursor.execute(sql, username)
              retval = cursor.fetchone()
              cursor.close()
              return retval
            except Exception as err:
              print "Transaction error in checkRecentAttempts " , err
              return False
      
    def log_login(self, ip, username, password):
        if not self.dberr:
            try:
                cursor = self.connection.cursor()
                sql = "INSERT INTO login_attempts SET "
                sql += " time=CURRENT_TIMESTAMP(), "
                sql += " ip=%s, "
                sql += " ip_numeric=INET_ATON(%s),"
                sql += " username=%s, "
                sql += " password=%s, "
                sql += " sensor_id=%s"
                cursor.execute(sql , (ip, ip, username, password, SENSOR_ID))
                self.connection.commit() 
            except Exception as msg:
                print "Error inserting login data to the database.  ", msg
                    
    def log_command(self, command, ip):
        global WHITELIST
        #whitelist functionality added by Josh Bauer <joshbauer3@gmail.com>
        if ip in WHITELIST:
            print 'command database entry skipped due to whitelisted ip: '+ip
        elif not self.dberr:
            try:
                cursor = self.connection.cursor()
                sql = "INSERT INTO executed_commands SET "
                sql += "command=%s, ip=%s, ip_numeric=INET_ATON(%s), sensor_id=%s"
                cursor.execute(sql , (cmd, ip, ip, SENSOR_ID))
                self.connection.commit() 
            except Exception as inst:
                print "Error inserting command data to the database.  ", inst
                