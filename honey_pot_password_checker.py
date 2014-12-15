#!/usr/bin/env python


from coret_config import *
from coret_fake import *
from twisted.python import log
from twisted.cred import checkers, credentials
from twisted.internet import defer
from zope.interface import implements
from twisted.cred import error as TCerror
from honeypot_db import *

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
                self.authorizedCredentials[data[0]] = self.authorizedCredentials[data[0]] + ',' + data[1].rstrip()
            else:
                self.authorizedCredentials[data[0]] = data[1].rstrip()
        print "Loaded " + str(i) + " accounts from " + FAKE_USERS_FILE
        self.checkCreds = HoneypotDB()

    def requestAvatarId(self, credentials):
        if hasattr(credentials, 'password'):
            if self.checkUserPass(credentials.username, credentials.password):
                return defer.succeed(credentials.username)
            else:
                return defer.fail(TCerror.UnauthorizedLogin())
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
        return defer.fail(TCerror.UnauthorizedLogin())
    
    def checkRecentAttempts(self,username):
        return self.checkCreds.check_recent(username)

    def checkUserPass(self, username, password):
        # Determine success or failure
        # Updated to limit one valid password per username after a valid combo is used
        # all passwords become valid for a given username 1 hour after last succesful login
        # password limiting added by Josh Bauer <joshbauer3@gmail.com>
        recentpass=self.checkRecentAttempts(username)
        if recentpass:
            if password == recentpass[0]:
                log.msg('login attempt [%s %s] succeeded' % (username, password))
                return True
            else:
                print 'login attempt [%s %s] failed' % (username, password)
                return False
        elif username in self.authorizedCredentials:
            passwords = self.authorizedCredentials[username].split(',')
            if passwords.count(password) > 0:
                log.msg('login attempt [%s %s] succeeded' % (username, password))
                return True
            else:
                print 'login attempt [%s %s] failed' % (username, password)
                return False
        else:
            print 'login attempt [%s %s] failed' % (username, password)
            return False
