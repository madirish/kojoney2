#!/usr/bin/env python
# This file is part of the Kojoney2 honeypot
#
# Main Developer - Justin C. Klein Keane <jukeane@sas.upenn.edu>
# Last updated 28 January 2013
#
# Look up country information from an IP using the hostip.info API

import urllib
import sys

if len(sys.argv) > 2:
    exit("Usage: kip2country <IP>")
ip = sys.argv[1]   
response = urllib.urlopen('http://api.hostip.info/get_html.php?ip=' + ip + '&position=true').read()
lines = response.split('\n')
print ip
print lines[0]
print lines[1]