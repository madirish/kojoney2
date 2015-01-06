#!/usr/bin/env python

from twisted.conch.ssh import session

from lib.kojoney_protocol import *


class KojoneySession:
    
    def __init__(self, avatar):
        """
        We don't use it, but the adapter is passed the avatar as its first
        argument.
        """

    def getPty(self, term, windowSize, attrs):
        pass

    def execCommand(self, proto, cmd):
        raise Exception("Error: Attempt to execute commands via remote CLI. No executing commands in kojoney_session.py")

    def openShell(self, trans):
        ep = KojoneyProtocol()
        ep.makeConnection(trans)
        trans.makeConnection(session.wrapProtocol(ep))

    def eofReceived(self):
        pass

    def closed(self):
        pass
