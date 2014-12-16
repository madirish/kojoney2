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

import os
import sys
import string
import imp

try:
    imp.find_module('MySQLdb')
    USE_DB = True
except ImportError:
    print "MySQLdb module wasn't found, skipping it."
    print "Maybe try:"
    print "pip install mysqldb"
    USE_DB = False
if USE_DB:
    import MySQLdb

try:
    imp.find_module('twisted')
except ImportError:
    print "Twisted module wasn't found so Kojoney can't run."
    print "Maybe try:"
    print "pip install twisted"
    sys.exit()
    
from twisted.cred import portal
from twisted.conch import error, avatar, interfaces as conchinterfaces
from twisted.conch.checkers import SSHPublicKeyDatabase
from twisted.conch.ssh import session
from twisted.internet import reactor

from coret_log import *
from coret_avatar import *
from coret_realm import *
from coret_session import *
from honey_pot_password_checker import *
from coret_factory import *


#
# First of all. Start logging now()!
#
start_logging()

#add missing tables to the database
#added by Josh Bauer <joshbauer3@gmail.com>
if USE_DB:
    subprocess.Popen('mysql -u %s --password=%s -h %s < create_tables.sql' % (DATABASE_USER, DATABASE_PASS, DATABASE_HOST) , stdout=subprocess.PIPE, shell=True)

"""
Running our fake shell over an SSH channel.
Log in with username "user" and password "password".
"""

from twisted.python import components
components.registerAdapter(CoretSession, CoretAvatar, session.ISession)

portal = portal.Portal(CoretRealm())
portal.registerChecker(HoneypotPasswordChecker())
CoretFactory.portal = portal

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
    reactor.listenTCP(int(port_num), CoretFactory())

reactor.run()