#!/usr/bin/env python
# This file is part of the Kojoney2 honeypot
#
# Main Developer - Justin C. Klein Keane <jukeane@sas.upenn.edu>
# Last updated 28 January 2013
#
# Look up country information from an IP using the hostip.info API

import urllib
import sys
import socket
import re

if len(sys.argv) > 2:
    exit("Usage: kip2country <IP or domain>")
ip = sys.argv[1]   
if not re.match('(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})', ip):
    ip = socket.gethostbyname(ip)
response = urllib.urlopen('http://api.hostip.info/get_html.php?ip=' + ip + '&position=true').read()
lines = response.split('\n')
print '\t\t' + lines[0]
print '\t\t' + lines[1]