#!/usr/bin/env python

"""
    This file is part of the Kojoney2 honeypot

    Main Developer - Justin C. Klein Keane <jukeane@sas.upenn.edu>
    Original Developer - Jose Antonio Coret <joxeankoret@yahoo.es>

    Kojoney - A honeypot that emulates a secure shell (SSH) server.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""

import sys
import imp

try:
    imp.find_module('twisted')
except ImportError:
    print "Twisted module wasn't found so Kojoney can't run."
    print "Maybe try:"
    print "pip install twisted"
    sys.exit()

from twisted.internet import reactor

from func.logging import *
from lib.kojoney_realm import *
from lib.kojoney_session import *
from lib.kojoney_password_checker import *
from lib.kojoney_factory import *
from lib.kojoney_db import KojoneyDB


#
# First of all. Start logging now()!
#
start_logging()

# update the database if necessary
HONEYPOTDB = KojoneyDB()
HONEYPOTDB.update_db()

CONFIG_LOGS = [sys.stderr, open(LOG_LOCATION, "a")]

"""
Running our fake shell over an SSH channel.
Log in with username "user" and password "password".
"""

from twisted.python import components
components.registerAdapter(KojoneySession, KojoneyAvatar, session.ISession)

portal = portal.Portal(KojoneyRealm())
portal.registerChecker(KojoneyPasswordChecker())
KojoneyFactory.portal = portal

#
# Am I running as root?
#

run_as_root = False

if os.name == "posix":
    if os.getuid() == 0:
        run_as_root = True
else:
    run_as_root = True

if run_as_root:
    port_nums = ROOT_CONFIG_PORTS
else:
    port_nums = CONFIG_PORTS

for port_num in port_nums:
    reactor.listenTCP(int(port_num), KojoneyFactory())

reactor.run()