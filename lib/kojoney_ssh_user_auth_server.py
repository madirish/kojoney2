#!/usr/bin/env python

from twisted.conch.ssh import userauth

from conf.fake_responses import *


# blatantly stolen from Kippo (and modified)    
from twisted.conch.ssh.common import NS


class KojoneySSHUserAuthServer(userauth.SSHUserAuthServer):
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