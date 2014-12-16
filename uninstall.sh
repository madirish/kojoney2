#!/bin/bash
# This file is part of the Kojoney2 honeypot
#
# Main Developer - Justin C. Klein Keane <jukeane@sas.upenn.edu>
# Original Developer - Jose Antonio Coret <joxeankoret@yahoo.es>
# Last updated 28 January 2013
#
# Kojoney2 install script
echo "******************************************"
echo " Kojoney2 Honeypot Uninstaller "
echo "******************************************"
echo "by Justin C. Klein Keane <justin@madirish.net>"
echo based on Kojoney, by Jose Antonio Coret
echo 
echo -e "Do you want to uninstall Kojoney2 (yes/no)? "
read res 

if [ $res = 'yes' ]; then
	echo " [-] Uninstalling ..."

	daemon_alive=`ps aux | grep /usr/bin/kojoneyd | grep -v grep | wc -l `

	if [ $daemon_alive -gt 0 ]; then
		echo " [-] Stopping kojoney daemon ..."

		if [ -f /etc/init.d/kojoney ]; then
			/etc/init.d/kojoney stop
		else
			echo " [-] Can't find a method to kill the daemon. Kill it manually."
			exit -1
		fi
		echo " [-] Waiting for a while"
		sleep 3
	fi

	echo " [-] Backing up downloads (you can manually delete them)"
	if [ -d /opt/kojoney_dls_bak/ ]; then
		mv /opt/kojoney/download/* /opt/kojoney_dls_bak/
	elif [ -d /opt/kojoney/download ]; then
		mv /opt/kojoney/download /opt/kojoney_dls_bak/
	fi
	if [ -d /opt/kojoney/kojoney.sqlite ]; then
		mv /opt/kojoney/kojoney.sqlite /opt/kojoney_dls_bak/
	fi

	echo " [-] Removing main directory"
	rm -fr /opt/kojoney

	echo " [-] Removing startup script"
	rm -f /etc/init.d/kojoney

	echo " [-] Removing symlinks"
	rm -f /usr/bin/kojoneyd /usr/bin/kojreport /usr/bin/kojreport-filter /usr/bin/kip2country \
	/usr/bin/kojhumans /usr/bin/kojsession /usr/bin/sessions_with_commands /usr/bin/commands_by_session_and_ip

	echo " [-] Removing man pages"
	rm -f /usr/share/man/man1/kip2country.1
	rm -f /usr/share/man/man1/kojhumans.1
	rm -f /usr/share/man/man1/kojreport-filter.1
	rm -f /usr/share/man/man1/kojreport.1
	echo " [-] Removing cron jobs"
	sed -i '/\/opt\/kojoney/ d' /etc/crontab
	echo " [-] Removing logrotate.d file"
	rm -f /etc/logrotate.d/kojoney
	
	echo " [-] Kojoney2 uninstall finished."
	echo
	echo "     NB: Any Kojoney2 databases are unaffected by this script."
fi