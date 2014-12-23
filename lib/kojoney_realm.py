#!/usr/bin/env python

from zope.interface import implements
from twisted.cred import portal

from lib.kojoney_avatar import *


class KojoneyRealm:
    try:
        implements(portal.IRealm)
    except:
        print "Unexpected error attempting to implement CoretRealm"

    def requestAvatar(self, avatarId, mind, *interfaces):
        return interfaces[0], KojoneyAvatar(avatarId), lambda: None
