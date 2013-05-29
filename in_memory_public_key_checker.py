#!/usr/bin/env python

from twisted.conch.checkers import SSHPublicKeyDatabase
class InMemoryPublicKeyChecker(SSHPublicKeyDatabase):

    def checkKey(self, credentials):
        return credentials.username == 'user' and \
            keys.getPublicKeyString(data=publicKey) == credentials.blob
