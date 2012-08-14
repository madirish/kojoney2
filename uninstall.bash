#!/bin/bash

echo -e "Do you want to uninstall Kojoney (yes/no)? "
read res 

if [ $res = 'yes' ]; then
	echo Uninstalling ...
	echo

	daemon_alive=`ps aux | grep /usr/bin/kojoneyd | grep -v grep | wc -l `

	if [ $daemon_alive -gt 0 ]; then
		echo Stopping kojoney daemon ...

		if [ -f /etc/init.d/kojoney ]; then
			/etc/init.d/kojoney stop
		else
			echo "Can't find a method to kill the daemon. Kill it manually."
			exit -1
		fi
		echo Waiting for a while
		sleep 3
	fi

	echo Removing main directory
	rm -fr /usr/share/kojoney

	echo Removing /etc/kojoney directory
	rm -fr /etc/kojoney

	echo Removing startup script
	rm -f /etc/init.d/kojoney

	echo Removing symlinks
	rm -f /usr/bin/kojoneyd /usr/bin/kojreport /usr/bin/kojreport-filter /usr/bin/kip2country \
	/usr/bin/kojhumans /usr/bin/kojsession /usr/bin/sessions_with_commands /usr/bin/commands_by_session_and_ip

	echo Uninstall finished
fi
