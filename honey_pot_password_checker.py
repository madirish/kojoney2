#!/usr/bin/env python


from coret_config import FAKE_USERS_FILE
from twisted.python import log
from twisted.cred import checkers, credentials
from twisted.internet import defer
from zope.interface import implements
from twisted.cred import error as TCerror
from honeypot_db import *
import os.path

# blatantly stolen from Kippo (and modified)
class HoneypotPasswordChecker:
    implements(checkers.ICredentialsChecker)

    credentialInterfaces = (credentials.IUsernamePassword,
        credentials.IPluggableAuthenticationModules)
    
    _authorized_credentials = {}
    _db_cred_checker = HoneypotDB()
    
    def __init__(self):
        global FAKE_USERS_FILE
        # Try a default location
        if not os.path.isfile(FAKE_USERS_FILE):
            FAKE_USERS_FILE = 'fake_users'
        file = open(FAKE_USERS_FILE, "r")
        i = 0
        for line in file:
            i += 1
            data = line.split(' ')
            if data[0] in self._authorized_credentials:
                self._authorized_credentials[data[0]] = self._authorized_credentials[data[0]] + ',' + data[1].rstrip()
            else:
                self._authorized_credentials[data[0]] = data[1].rstrip()
        print "Loaded " + str(i) + " accounts from " + FAKE_USERS_FILE

    """
    requestAvatarId overloads the ICredentialsChecker -
    https://twistedmatrix.com/documents/8.2.0/api/twisted.cred.checkers.ICredentialsChecker.html
    """
    def requestAvatarId(self, credentials):
        if hasattr(credentials, 'password'):
            if self._check_user_creds(credentials.username, credentials.password):
                return defer.succeed(credentials.username)
            else:
                return defer.fail(TCerror.UnauthorizedLogin())
        elif hasattr(credentials, 'pamConversion'):
            return self._check_pam_user(credentials.username,
                credentials.pamConversion)
        return defer.fail(TCerror.UnhandledCredentials())

    def _check_pam_user(self, username, pamConversion):
        r = pamConversion((('Password:', 1),))
        return r.addCallback(self._callback_check_pam_user, username)

    def _callback_check_pam_user(self, responses, username):
        for response, zero in responses:
            if self._check_user_creds(username, response):
                return defer.succeed(username)
        return defer.fail(TCerror.UnauthorizedLogin("Unauthorized login for %s" % username))

    def _check_user_creds(self, username, password):
        # Determine success or failure
        # Updated to limit one valid password per username after a valid combo is used
        # all passwords become valid for a given username 1 hour after last succesful login
        # password limiting added by Josh Bauer <joshbauer3@gmail.com>
        recentpass=self._db_cred_checker.check_recent(username)
        if recentpass:
            if password == recentpass[0]:
                log.msg('login attempt [%s %s] succeeded' % (username, password))
                return True
            else:
                print 'login attempt [%s %s] failed' % (username, password)
                return False
        elif username in self._authorized_credentials:
            passwords = self._authorized_credentials[username].split(',')
            if passwords.count(password) > 0:
                log.msg('login attempt [%s %s] succeeded' % (username, password))
                return True
            else:
                print 'login attempt [%s %s] failed' % (username, password)
                return False
        else:
            print 'login attempt [%s %s] failed' % (username, password)
            return False
