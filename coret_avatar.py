#!/usr/bin/env python

from twisted.conch.ssh import session
from twisted.conch import avatar
class CoretAvatar(avatar.ConchUser):

    def __init__(self, username):
        global FAKE_USERNAME
        avatar.ConchUser.__init__(self)
        self.username = username
        FAKE_USERNAME = username
        self.channelLookup.update({'session':session.SSHSession})