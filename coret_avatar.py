#!/usr/bin/env python

from twisted.conch.ssh import session
from twisted.conch import avatar
class CoretAvatar(avatar.ConchUser):

    def __init__(self, username):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.channelLookup.update({'session':session.SSHSession})