# This file is part of the Kojoney2 honeypot
#
# Main Developer - Justin C. Klein Keane <jukeane@sas.upenn.edu>
# Original Developer - Jose Antonio Coret <joxeankoret@yahoo.es>
# Last updated 29 January 2013
#   
# Kojoney2 configuration file
#
# We can run Kojoney2 in root or non root mode. When running as root we need to
# modify parameters that likes ROOT_*. When running as a normal user we need to
# modify the parameters without the ROOT_ prefix.
#
# In example: To change the listening port when running as root the parameter 
# is ROOT_CONFIG_PORTS. When running as a normal user the parameter is 
# CONFIG_PORTS
#

import os
import sys

DEBUG = False

FAKE_USERS_FILE = "conf/fake_users"

# List of ip addresses to exclude from database entries
# whitelist functionality added by Josh Bauer <joshbauer3@gmail.com>
# Ex: WHITELIST = ['127.0.0.1', '192.168.0.3', '10.0.0.2']
WHITELIST = []
# List of ip addresses to raise alerts for
# blacklist functionality added by Josh Bauer <joshbauer3@gmail.com>
# Ex: BLACKLIST = ['127.0.0.0/24', '192.168.0.0/16', '10.0.0.0/31']
BLACKLIST = []

# Sensor id should be unique if you have more than one Kojoney2 instance
# logging to the same database.
SENSOR_ID = 1

if os.getuid() == 0:
#################################################################
# START OF KOJONEY CONFIGURATION - RUNNING AS ROOT
#################################################################

#
# NOTE: THE INDENTATION IN ALL THE CONFIGURATION DIRECTIVES IS OBLIGATORIOUS
#

#
# ROOT_CONFIG_LOGS - Log file(s). You can specify one, two or more files to log 
#
# Examples:
#   
#  ROOT_CONFIG_LOGS = [sys.stderr] 
#       Output to stdout and stderr devices.
#
#  ROOT_CONFIG_LOGS = [open("/var/log/honeypot.log", "a")]
#       Append output to file /var/log/honeypot.log.
#
#  ROOT_CONFIG_LOGS = [sys.stderr, open("/var/log/honeypot.log", "a"), open("/tmp/session.log", "w")]
#       Append output to file /var/log/honeypot.log, output to stderr and stdout, and output to /tmp/session.log 
#       overwriting any previous file contents.
#
    ROOT_CONFIG_LOGS = [sys.stderr, open("log/honeypot.log", "a")]

#
# ROOT_CONFIG_PORTS - Listening ports. You can specify one, two or more ports to listen.
#
# Examples:
#
# ROOT_CONFIG_PORTS = [22]
#       Listen only in the standard SSH port (22/tcp).
#
# ROOT_CONFIG_PORTS = [22, 443]
#       Listen in the standard SSH port (22/tcp) and also in the 443 port (https).
#
    ROOT_CONFIG_PORTS = [22]

#
# STANDARD CONFIGURATION OPTIONS
#
#
# When an intruder tries to download file with CURL or WGET, will I download the file? And where?
#
    DOWNLOAD_REAL_FILE = True
    DOWNLOAD_REAL_DIR  = "download/"

#################################################################
# END OF KOJONEY CONFIGURATION - RUNNING AS ROOT
#################################################################
else:
#################################################################
# START OF KOJONEY CONFIGURATION - RUNNING AS NORMAL USER
#################################################################

#
# NOTE: THE INDENTATION IN ALL THE CONFIGURATION DIRECTIVES IS OBLIGATORIOUS
#

#
# CONFIG_LOGS - Log file(s). You can specify one, two or more files to log. 
#
# Examples:
#   
#  CONFIG_LOGS = [sys.stderr] 
#       Output to stdout and stderr devices.
#
#  CONFIG_LOGS = [open("/var/log/honeypot.log", "a")]
#       Append output to file /var/log/honeypot.log.
#
#  CONFIG_LOGS = [sys.stderr, open("/var/log/honeypot.log", "a"), open("/tmp/session.log", "w")]
#       Append output to file /var/log/honeypot.log, output to stderr and stdout, and output to /tmp/session.log 
#       overwriting any previous file contents.
#
    CONFIG_LOGS = [sys.stderr, open("/tmp/honeypot.log", "a")]

#
# ROOT_CONFIG_PORTS - Listening ports. You can specify one, two or more ports to listen.
#
# Examples:
#
# ROOT_CONFIG_PORTS = [5022]
#       Listen in the port 5022.
#
# ROOT_CONFIG_PORTS = [5022, 5999]
#       Listen in the ports 5022, 5999
#
    CONFIG_PORTS = [2222]
#
# STANDARD CONFIGURATION OPTIONS
#
#
# When an intruder tries to download file with CURL or WGET, will I download the file? And where?
#
    DOWNLOAD_REAL_FILE = True
    DOWNLOAD_REAL_DIR  = "download/"

#################################################################
# END OF KOJONEY CONFIGURATION - RUNNING AS A NORMAL USER
#################################################################
