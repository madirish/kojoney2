#!/usr/bin/env python

"""
    This file is part of the Kojoney2 honeypot

    Main Developer - Justin C. Klein Keane <jukeane@sas.upenn.edu>
    Original Developer - Jose Antonio Coret <joxeankoret@yahoo.es>
    Last updated: January 28, 2013

    Kojoney - A honeypot that emulates a secure shell (SSH) server.

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

from twisted.cred import portal, checkers, credentials, error
from twisted.conch import error, avatar, interfaces as conchinterfaces
from twisted.conch.checkers import SSHPublicKeyDatabase
from twisted.conch.ssh import factory, userauth, connection, keys, session, transport
from twisted.internet import reactor, protocol, defer
from twisted.python import log
from zope.interface import implements

from coret_honey import *
from coret_config import *
from coret_fake import *
from coret_log import *

#
# First of all. Start logging now()!
#
start_logging()

# Global holder
FAKE_USERNAME = ""

"""
Running our fake shell over an SSH channel.
Log in with username "user" and password "password".
"""
class CoretAvatar(avatar.ConchUser):

    def __init__(self, username):
        global FAKE_USERNAME
        avatar.ConchUser.__init__(self)
        self.username = username
        FAKE_USERNAME = username
        self.channelLookup.update({'session':session.SSHSession})
        #self.channelLookup.update({'session': CoretSession})

class CoretRealm:
    try:
        implements(portal.IRealm)
    except:
        print "BUG #1255822: " + str(sys.exc_info()[1])
        print ""
        print "For more details see https://sourceforge.net/tracker/index.php?func=detail&aid=1255822&group_id=143961&atid=758336"
        print "If you are using standard Ubuntu Hoary packages I recommend you to download and compile the source code of Zope Interfaces as well as Twisted libraries."
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
            connection = MySQLdb.connect(host=DATABASE_HOST, user=DATABASE_USER, passwd=DATABASE_PASS, db=DATABASE_NAME)
            cursor = connection.cursor()
            escaped_command = connection.escape_string(self.lastCmd)
            escaped_ip = connection.escape_string(self.transport.session.conn.transport.transport.getPeer()[1])
            cursor.execute("INSERT INTO executed_commands SET command='%s', ip='%s'" % (escaped_command, escaped_ip)) 
            retvalue = processCmd(self.lastCmd, self.transport, FAKE_USERNAME, escaped_ip, self.fake_workingdir)
            self.lastCmd = ""
            
            (printlinebreak, ret_workingdir, ret_username) = retvalue
            self.fake_workingdir = ret_workingdir
            FAKE_USERNAME = ret_username
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

publicKey = FAKE_SSH_KEY

privateKey = FAKE_SSH_PRIVKEY

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

# blatantly stolen from Kippo (and modified)    
from twisted.conch.ssh.common import NS, getNS
class HoneyPotSSHUserAuthServer(userauth.SSHUserAuthServer):
    def serviceStarted(self):
        userauth.SSHUserAuthServer.serviceStarted(self)
        self.bannerSent = False

    def sendBanner(self):
        if self.bannerSent:
            return
        self.transport.sendPacket(userauth.MSG_USERAUTH_BANNER, NS(FAKE_SSH_SERVER_VERSION+'\r\n') + NS('en'))
        self.bannerSent = True

    def ssh_USERAUTH_REQUEST(self, packet):
        self.sendBanner()
        return userauth.SSHUserAuthServer.ssh_USERAUTH_REQUEST(self, packet)
    
# blatantly stolen from Kippo (and modified)
class HoneypotPasswordChecker:
    implements(checkers.ICredentialsChecker)

    credentialInterfaces = (credentials.IUsernamePassword,
        credentials.IPluggableAuthenticationModules)
    
    authorizedCredentials = {}
    
    def __init__(self):
        file = open(FAKE_USERS_FILE, "r")
        i = 0
        for line in file:
            i += 1
            data = line.split(' ')
            if data[0] in self.authorizedCredentials:
                self.authorizedCredentials[data[0]] = self.authorizedCredentials[data[0]] + data[1].rstrip() + ','
            else:
                self.authorizedCredentials[data[0]] = data[1].rstrip() + ','
        print "Loaded " + str(i) + " accounts from " + FAKE_USERS_FILE

    def requestAvatarId(self, credentials):
        if hasattr(credentials, 'password'):
            if self.checkUserPass(credentials.username, credentials.password):
                return defer.succeed(credentials.username)
            else:
                return defer.fail(error.UnauthorizedLogin())
        elif hasattr(credentials, 'pamConversion'):
            return self.checkPamUser(credentials.username,
                credentials.pamConversion)
        return defer.fail(error.UnhandledCredentials())

    def checkPamUser(self, username, pamConversion):
        r = pamConversion((('Password:', 1),))
        return r.addCallback(self.cbCheckPamUser, username)

    def cbCheckPamUser(self, responses, username):
        for response, zero in responses:
            if self.checkUserPass(username, response):
                return defer.succeed(username)
        return defer.fail(error.UnauthorizedLogin())

    def checkUserPass(self, username, password):
        if username in self.authorizedCredentials:
            passwords = self.authorizedCredentials[username].split(',')
            if passwords.count(password) > 0:
                print '%s authenticated with password' % (username)
                print 'login attempt [%s/%s] succeeded' % (username, password)
                return True
            else:
                print 'login attempt [%s/%s] failed' % (username, password)
                return False
        else:
            print 'login attempt [%s/%s] failed' % (username, password)
            return False


class CoretFactory(factory.SSHFactory):
    publicKeys = {'ssh-rsa': keys.getPublicKeyString(data=publicKey)}
    privateKeys = {'ssh-rsa': keys.getPrivateKeyObject(data=privateKey)}
    services = {
                'ssh-userauth': HoneyPotSSHUserAuthServer,
                'ssh-connection': connection.SSHConnection
                }
    
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
portal.registerChecker(HoneypotPasswordChecker())
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
