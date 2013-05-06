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
import os
import sys

from coret_config import *

from twisted.python import log

def log_machine(data):
    print "Log_machine: " + data
    pass

def log_cmd_session(session, data):
    print "Log_cmd_session: " + session + " :: " + data
    pass

def start_logging():
    if os.getuid() == 0:
        log_file_list = ROOT_CONFIG_LOGS
    else:
        log_file_list = CONFIG_LOGS

    for log_file in log_file_list:
        print "Ok, starting log to "  + str(log_file)
        log.startLogging(log_file)
        #log.addObserver(koj_watcher)
    
def koj_watcher(eventDict):
    """Custom emit for FileLogObserver"""
    text = log.textFromEventDict(eventDict)
    if text is None:
        return
    fmtDict = {'text': text.replace("\n", "\n\t")}
    msgStr = log._safeFormat("%(text)s\n", fmtDict)
