#!/bin/bash
# Modified by Justin C. Klein Keane <jukeane@sas.upenn.edu>
# Last updated 15 Aug, 2012
# This script will send a daily honeypot report to the configured email address
#DATE=`date '+%Y-%m-%d' --date='1 day ago'`
# email subject
#SUBJECT="Kojoney Daily Report"
# email to
EMAIL="root@localhost"
# email message
#EMAILMESSAGE="/usr/share/kojoney/report.txt"
# generate report
#/usr/share/kojoney/kojreport-filter /var/log/honeypot.log $DATE 0 0 1 > $EMAILMESSAGE
# send email using /bin/mail
#/usr/bin/mutt -s "$SUBJECT" "$EMAIL" < $EMAILMESSAGE

KOJLOG=/var/log/honeypot.log-$(date +%Y%m%d)
/usr/share/kojoney/kojreport $KOJLOG | mail -s "Kojoney Report" $EMAIL
logger Kojoney report generated and sent.
