#!/usr/bin/env python

import MySQLdb
import string
from twisted.internet import protocol
from coret_fake import *
from coret_honey import *
from coret_config import *

# Global holder
FAKE_USERNAME = ""

class CoretProtocol(protocol.Protocol):
    """
    This is our Coret protocol that we will run over SSH
    """
    lastCmd = ""
    fake_workingdir = "/"


    def connectionMade(self):
        global FAKE_USERNAME, FAKE_PROMPT, FAKE_CWD, FAKE_HOMEDIRS
        self.fake_username = FAKE_USERNAME
        if FAKE_USERNAME in FAKE_HOMEDIRS:
            self.fake_workingdir = FAKE_HOMEDIRS[FAKE_USERNAME]
        else:
            FAKE_CWD = "/"
        if self.fake_username == 'root':
            FAKE_PROMPT = string.replace(FAKE_PROMPT, '$', '#')
        self.transport.write('Welcome to ' + str(FAKE_OS) + '!\r\n\r\n' +str(FAKE_PROMPT))

    #Modified by Martin Barbella for database support,
    #backspace bug fix, arrow key bug fix (by ignoring arrow input),
    #removal of line breaks from commands (to prevent logs from being broken).
    def dataReceived(self, data):
        global FAKE_PROMPT, FAKE_USERNAME, FAKE_CWD
        
        if data == '\r':
            self.lastCmd = string.replace(self.lastCmd, '\r', '')
            self.lastCmd = string.replace(self.lastCmd, '\n', '')
            ip = self.transport.session.conn.transport.transport.getPeer()[1]
            
            #whitelist functionality added by Josh Bauer <joshbauer3@gmail.com>
            if ip in WHITELIST:
                print 'command database entry skipped due to whitelisted ip: '+ip
            else:
                try:
                    connection = MySQLdb.connect(host=DATABASE_HOST, 
                                                 user=DATABASE_USER, 
                                                 passwd=DATABASE_PASS, 
                                                 db=DATABASE_NAME)
                    cursor = connection.cursor()
                    sql = "INSERT INTO executed_commands SET "
                    sql += "command=%s, ip=%s, ip_numeric=INET_ATON(%s), sensor_id=%s"
                    cursor.execute(sql , (self.lastCmd, ip, ip, SENSOR_ID))
                    connection.commit() 
                    connection.close()
                except Exception as inst:
                    print "Error inserting command data to the database.  ", inst
                
            # "Execute" the command(s)
            # handle multiple commands delimited by semi-colons
            if (len(self.lastCmd.split(';')) > 1):
                print "Handling semi-colon delimited commands"
                for command in self.lastCmd.split(';'):
                    retvalue = processCmd(command, 
                                          self.transport, 
                                          FAKE_USERNAME, 
                                          ip,  
                                          self.fake_workingdir)
                    (printlinebreak, self.fake_workingdir, FAKE_USERNAME) = retvalue
            else:
                retvalue = processCmd(self.lastCmd, 
                                      self.transport, 
                                      FAKE_USERNAME, 
                                      ip, 
                                      self.fake_workingdir)
                (printlinebreak, self.fake_workingdir, FAKE_USERNAME) = retvalue
                
            self.lastCmd = ""
            if FAKE_USERNAME == 'root':
                FAKE_PROMPT = string.replace(FAKE_PROMPT, '$', '#')
            else:
                FAKE_PROMPT = string.replace(FAKE_PROMPT, '#', '$')
            if printlinebreak == 1:
                data = '\r\n'
            
            data += str(FAKE_PROMPT)
        elif data == '\x03': #^C
            try:
                self.transport.loseConnection()
            finally:
                return
        elif data == '\x7F':
            if len(self.lastCmd) > 0:
                self.lastCmd = self.lastCmd[0:len(self.lastCmd) - 1]
                self.transport.write("\x1B\x5B\x44 \x1B\x5B\x44");
            return
        elif data == "\x1B\x5B\x41":
            #ignore up arrow
            return
        elif data == "\x1B\x5B\x42":
            #ignore down arrow
            return
        elif data == "\x1B\x5B\x43":
            #ignore right arrow
            return
        elif data == "\x1B\x5B\x44":
            #ignore left arrow
            return
        else:
            self.lastCmd += data

        self.transport.write(data)