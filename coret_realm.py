#!/usr/bin/env python

from coret_avatar import *

class CoretRealm:
    try:
        implements(portal.IRealm)
    except:
        print "Unexpected error attempting to implement CoretRealm"

    def requestAvatar(self, avatarId, mind, *interfaces):
        return interfaces[0], CoretAvatar(avatarId), lambda: None
