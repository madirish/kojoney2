"""
    This file is part of the Kojoney2 honeypot

    Main Developer - Justin C. Klein Keane <jukeane@sas.upenn.edu>
    Original Developer - Jose Antonio Coret <joxeankoret@yahoo.es>
    Last updated 28 January 2013

    This file supports the logging functionality of the honeypot.

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

import re
import socket
import struct
import syslog
import subprocess

from twisted.python import log

from conf.coret_config import *
from honeypot_db import HoneypotDB


def log_machine(data):
    print "Log_machine: " + data
    pass

def log_cmd_session(session, data):
    print "Log_cmd_session: " + session + " :: " + data
    pass

def start_logging():
    # Add a log observer to modify logging on the fly
    log.addObserver(login_logger)
    if os.getuid() == 0:
        log_file_list = ROOT_CONFIG_LOGS
    else:
        log_file_list = CONFIG_LOGS

    for log_file in log_file_list:
        print "Ok, starting log to "  + str(log_file)
        log.startLogging(log_file)

#blacklist functionality added by Josh Bauer <joshbauer3@gmail.com>
def is_blacklisted(ip):
    ip_int=struct.unpack("!L", socket.inet_aton(ip))[0]
    for net in BLACKLIST:
        startip = net.split('/')[0]
        startip_int = struct.unpack("!L", socket.inet_aton(startip))[0]
        endip_int = startip_int + (pow(2,32 - int(net.split('/')[1]))-1)
        if ip_int >= startip_int and ip_int <= endip_int:
            return True
    return False
        
#enters successful login attempts into the database
#added by Josh Bauer <joshbauer3@gmail.com>
"""
The log observer watches logs as they are being generated.
We want to intercept entries from the whitelist and not
log them, and entries from the blacklist and do something
more with them.
"""
def login_logger(eventDict):
    log_message = log.textFromEventDict(eventDict)
    matchstring = 'login attempt \[(\S+) (\S+)\] (\w+)'
    msg = re.search(matchstring, log_message)
    if msg:
        ip=eventDict['system'].split(',')[-1]
        username=msg.group(1)
        password=msg.group(2)
        # Whitelist trumps blacklist
        if ip in WHITELIST:
            print 'Logging skipped due to whitelist for ' + ip
        else:
            if ip in BLACKLIST:
                print 'BLACKLISTED IP ' + ip + ' (successful login with username: ' + username + ')'
                syslog.syslog('BLACKLISTED IP: '+ip+' (successful login with username: '+username+')')
            dbconn = HoneypotDB()
            dbconn.log_login(ip, username, password)
            subprocess.Popen('/usr/bin/python %s %s ' % (NMAP_SCRIPT, ip), stdout=subprocess.PIPE, shell=True)
