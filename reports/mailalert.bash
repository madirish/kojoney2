#!/bin/bash
# This file is part of the Kojoney2 honeypot
#
# Main Developer - Justin C. Klein Keane <jukeane@sas.upenn.edu>
# Original Developer - Jose Antonio Coret <joxeankoret@yahoo.es>
# Last updated 28 January 2013
#
# This script will send a honeypot report to the configured email address
#
EMAIL="root@localhost"

KOJLOG=/var/log/honeypot.log-$(date +%Y%m%d)
/opt/kojoney/kojreport $KOJLOG | mail -s "Kojoney2 Report" $EMAIL
logger Kojoney2 report generated and sent.
