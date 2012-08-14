#!/usr/bin/env python

"""
    Kojoney - A honeypot that emules a secure shell (SSH) server.
    Copyright (C) 2005 Jose Antonio Coret

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""

import os
import sys
import string
import MySQLdb

from twisted.cred import portal, checkers
from twisted.conch import error, avatar
from twisted.conch.checkers import SSHPublicKeyDatabase
from twisted.conch.ssh import factory, userauth, connection, keys, session, transport
from twisted.internet import reactor, protocol, defer
from twisted.python import log
from zope.interface import implements

from coret_users import add_users
from coret_honey import *
from coret_config import *
from coret_fake import *
from coret_log import *

#
# First of all. Start logging now()!
#
start_logging()
userauth.conch_mysql_connect(DATABASE_USER, DATABASE_PASS, DATABASE_HOST, DATABASE_NAME)

"""
Running our fake shell over an SSH channel.
Log in with username "user" and password "password".
"""
class CoretAvatar(avatar.ConchUser):

    def __init__(self, username):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.channelLookup.update({'session':session.SSHSession})

class CoretRealm:
    try:
        implements(portal.IRealm)
    except:
        print "BUG #1255822: " + str(sys.exc_info()[1])
        print ""
        print "For more details see https://sourceforge.net/tracker/index.php?func=detail&aid=1255822&group_id=143961&atid=758336"
        print "If you are using standar Ubuntu Hoary packages I recommend you to download and compile the source code of Zope Interfaces as well as Twisted libraries."
        print ""
        print "NOTE: If you known how to solve this problem, please, contact me at joxeankoret@yahoo.es"
        print ""
        print "Sorry for the inconvenience"
        print ""

    def requestAvatar(self, avatarId, mind, *interfaces):
        return interfaces[0], CoretAvatar(avatarId), lambda: None

class CoretProtocol(protocol.Protocol):
    """
    This is our Coret protocol that we will run over SSH
    """
    lastCmd = ""


    def connectionMade(self):
        print self.transport
        self.transport.write('Welcome to ' + str(FAKE_OS) + '!\r\n\r\n' +str(FAKE_PROMPT))

    #Modified by Martin Barbella for database support,
    #backspace bug fix, arrow key bug fix (by ignoring arrow input),
    #removal of line breaks from commands (to prevent logs from being broken).
    def dataReceived(self, data):
        global FAKE_PROMPT

        if data == '\r':
            self.lastCmd = string.replace(self.lastCmd, '\r', '')
            self.lastCmd = string.replace(self.lastCmd, '\n', '')
            connection = MySQLdb.connect(host=DATABASE_HOST, user=DATABASE_USER, passwd=DATABASE_PASS, db=DATABASE_NAME)
            cursor = connection.cursor()
            escaped_command = connection.escape_string(self.lastCmd)
            escaped_ip = connection.escape_string(self.transport.session.conn.transport.transport.getPeer()[1])
            cursor.execute("INSERT INTO executed_commands SET command='%s', ip='%s'" % (escaped_command, escaped_ip))
            retvalue = processCmd(self.lastCmd, self.transport)
            self.lastCmd = ""
            #data = '\r\n' + str(FAKE_PROMPT) 
            
            if retvalue != 0:
                data = '\r\n'
            else:
                data = ""
            
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

publicKey = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAGEArzJx8OYOnJmzf4tfBEvLi8DVPrJ3/c9k2I/Az64fxjHf9imyRJbixtQhlH9lfNjUIx+4LmrJH5QNRsFporcHDKOTwTTYLh5KmRpslkYHRivcJSkbh/C+BR3utDS555mV'

privateKey = """-----BEGIN RSA PRIVATE KEY-----
MIIByAIBAAJhAK8ycfDmDpyZs3+LXwRLy4vA1T6yd/3PZNiPwM+uH8Yx3/YpskSW
4sbUIZR/ZXzY1CMfuC5qyR+UDUbBaaK3Bwyjk8E02C4eSpkabJZGB0Yr3CUpG4fw
vgUd7rQ0ueeZlQIBIwJgbh+1VZfr7WftK5lu7MHtqE1S1vPWZQYE3+VUn8yJADyb
Z4fsZaCrzW9lkIqXkE3GIY+ojdhZhkO1gbG0118sIgphwSWKRxK0mvh6ERxKqIt1
xJEJO74EykXZV4oNJ8sjAjEA3J9r2ZghVhGN6V8DnQrTk24Td0E8hU8AcP0FVP+8
PQm/g/aXf2QQkQT+omdHVEJrAjEAy0pL0EBH6EVS98evDCBtQw22OZT52qXlAwZ2
gyTriKFVoqjeEjt3SZKKqXHSApP/AjBLpF99zcJJZRq2abgYlf9lv1chkrWqDHUu
DZttmYJeEfiFBBavVYIF1dOlZT0G8jMCMBc7sOSZodFnAiryP+Qg9otSBjJ3bQML
pSTqy7c3a2AScC/YyOwkDaICHnnD3XyjMwIxALRzl0tQEKMXs6hH8ToUdlLROCrP
EhQ0wahUTCk1gKA4uPD6TMTChavbh4K63OvbKg==
-----END RSA PRIVATE KEY-----"""

class InMemoryPublicKeyChecker(SSHPublicKeyDatabase):

    def checkKey(self, credentials):
        return credentials.username == 'user' and \
            keys.getPublicKeyString(data=publicKey) == credentials.blob

class CoretSession:
    
    def __init__(self, avatar):
        """
        We don't use it, but the adapter is passed the avatar as its first
        argument.
        """

    def getPty(self, term, windowSize, attrs):
        pass

    def execCommand(self, proto, cmd):
        raise Exception("no executing commands")

    def openShell(self, trans):
        ep = CoretProtocol()
        ep.makeConnection(trans)
        trans.makeConnection(session.wrapProtocol(ep))

    def eofReceived(self):
        pass

    def closed(self):
        pass

from twisted.python import components
components.registerAdapter(CoretSession, CoretAvatar, session.ISession)

class CoretFactory(factory.SSHFactory):
    publicKeys = {'ssh-rsa': keys.getPublicKeyString(data=publicKey)}
    privateKeys = {'ssh-rsa': keys.getPrivateKeyObject(data=privateKey)}
    services = {'ssh-userauth': userauth.SSHUserAuthServer, 'ssh-connection': connection.SSHConnection}
    
    def buildProtocol(self, addr):
        t = transport.SSHServerTransport()
        #
        # Fix for BUG 1463701 "NMap recognizes Kojoney as a Honeypot"
        #
        t.ourVersionString = FAKE_SSH_SERVER_VERSION
        t.supportedPublicKeys = self.privateKeys.keys()
        if not self.primes:
            ske = t.supportedKeyExchanges[:]
            ske.remove('diffie-hellman-group-exchange-sha1')
            t.supportedKeyExchanges = ske
        t.factory = self
        return t

portal = portal.Portal(CoretRealm())

#
# Register the fake username and password
#
passwdDB = checkers.InMemoryUsernamePasswordDatabaseDontUse()
add_users(passwdDB)
portal.registerChecker(passwdDB)
portal.registerChecker(InMemoryPublicKeyChecker())

CoretFactory.portal = portal

#
# Am I running as root?
#

run_as_root = False

if os.name == "posix":
    if os.getuid() == 0:
        run_as_root = True
else:
    run_as_root = True

if run_as_root:
    port_nums = ROOT_CONFIG_PORTS
else:
    port_nums = CONFIG_PORTS

for port_num in port_nums:
    reactor.listenTCP(int(port_num), CoretFactory())

reactor.run()
