#!/usr/bin/env python

from coret_fake import *
from twisted.conch.ssh import userauth
from honeypot_db import HoneypotDB

# blatantly stolen from Kippo (and modified)    
from twisted.conch.ssh.common import NS, getNS
class HoneyPotSSHUserAuthServer(userauth.SSHUserAuthServer):
    def serviceStarted(self):
        userauth.SSHUserAuthServer.serviceStarted(self)
        self.bannerSent = False

    def sendBanner(self):
        if self.bannerSent:
            return
        self.transport.sendPacket(userauth.MSG_USERAUTH_BANNER, 
                                  NS(FAKE_SSH_SERVER_VERSION+'\r\n') + NS('en'))
        self.bannerSent = True

    def ssh_USERAUTH_REQUEST(self, packet):
        self.sendBanner()
        return userauth.SSHUserAuthServer.ssh_USERAUTH_REQUEST(self, packet)