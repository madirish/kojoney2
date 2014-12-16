#!/bin/bash
# This file is part of the Kojoney2 honeypot
#
# Main Developer - Justin C. Klein Keane <jukeane@sas.upenn.edu>
# Original Developer - Jose Antonio Coret <joxeankoret@yahoo.es>
# Last updated 29 January 2013
#
# Kojoney2 install script

function die
{
	echo Error at $1
	echo Kojoney2 installation failed
	exit 1
}

if [ "$(id -u)" != "0" ]; then
	echo "This script must be run as root, please use sudo"
    exit 1
fi


KOJONEY_PATH=/opt/kojoney

clear
echo "******************************************"
echo " Kojoney2 Honeypot Installer "
echo "******************************************"
echo "by Justin C. Klein Keane <justin@madirish.net>"
echo "based on Kojoney, by Jose Antonio Coret"
echo 
echo "Step 1 of 9 - Checking for prerequisite dependencies..."

# Do prerequisites for RedHat systems
if [ -e /etc/redhat-release ]; then
	# Install the Python libraries
	if rpm -q python-crypto | grep not ; then
	  echo Python crypto library not installed!
	  yum install python-crypto
	fi
	if rpm -q python-twisted-conch | grep not ; then
	  echo " [+] Python Twisted Conch library not installed!"
	  yum install python-twisted-conch
	fi
	if rpm -q python-zope-interface | grep not ; then
	  echo " [+] Zope library not installed!"
	  yum install python-zope-interface
	fi
fi
echo " [+] Dependency check complete."
echo 
echo "Step 2 of 9 - Licenses"
echo Kojoney2 is bound by a number of license agreements
echo which are included in the install path.
echo
echo -e "Do you accept the GPL license terms (yes/no) ?"
read license_accept

if [ "$license_accept" = 'yes' ]; then
	echo All licenses accepted
	echo
else
	echo You need to accept the licenses to install Kojoney2.
	echo Exiting...
	echo
	exit
fi

echo 
echo "Step 3 of 9 - Creating directory structure"
if [ -d $KOJONEY_PATH ]; then
	echo " [-] Kojoney2 directory $KOJONEY_PATH already exists."
	echo " [-] Please uninstall Kojoney2 with the uninstall.bash script, then try again."
	echo " [-] Exiting..."
	exit
else
	mkdir $KOJONEY_PATH || die "Step 3 - couldn't create directory $KOJONEY_PATH" 
fi

echo " [+] Creating directory for Kojoney2 configuration files"
mkdir $KOJONEY_PATH/etc || die "Step 3 - couldn't create directory $KOJONEY_PATH/etc" 
echo " [+] Creating directory for url archives"
mkdir $KOJONEY_PATH/download || die "Step 3 - couldn't create directory $KOJONEY_PATH/download" 
echo " [+] Creating directory for application logs"
mkdir $KOJONEY_PATH/log || die "Step 3 - couldn't create directory $KOJONEY_PATH/log" 
cp *.py* $KOJONEY_PATH
cp *.sql* $KOJONEY_PATH
cp fake_users $KOJONEY_PATH/etc/
cp -f reports/* $KOJONEY_PATH 
echo " [+] Kojoney files installed"
echo 
echo " [+] Installed at $KOJONEY_PATH"
echo

echo 
echo "Step 4 of 9 - Email reporting configuration"
# Daily reports
echo -e "Would you like daily reports e-mailed? (yes/no)"
read want_reports
if [ $want_reports == 'yes' ]; then
	echo -e "Please enter e-mail of desired recipient:"
	read email_to
	sed -i "s/root\@localhost/$email_to/g" $KOJONEY_PATH/mailalert.bash
	if ! cat /etc/crontab | grep mailalert ; then
		echo "  01  00  *  *  * root $KOJONEY_PATH/mailalert.bash > /dev/null" >> /etc/crontab
		echo " [+] Cron for report e-mail scheduled in /etc/crontab"
	fi
fi
echo 
echo "Step 5 of 9 - Housekeeping configuration"
# Assume logrotate is installed
touch /etc/logrotate.d/kojoney
echo "/var/log/honeypot.log {" > /etc/logrotate.d/kojoney
echo "    sharedscripts" >> /etc/logrotate.d/kojoney
echo "    daily" >> /etc/logrotate.d/kojoney
echo "    endscript" >> /etc/logrotate.d/kojoney
echo "}" >> /etc/logrotate.d/kojoney
echo " [+] Logrotate scheduled"
echo 
echo "Step 6 of 9 - Honeypot customization"
# Customize honeypot
echo Please enter the fully qualified hostname for your honeypot:
read user_fqdn
sed -i "s/fqdn_placeholder/$user_fqdn/g" $KOJONEY_PATH/coret_fake.py
echo 
echo "Step 7 of 9 - Installing documentation "
echo " [+] Installing man pages"

if [ -d /usr/share/man/man1 ]; then
	cp docs/man/*.1 /usr/share/man/man1/ || die "Step 9 - copying man1 files" 
else
	echo " Man path not found in /usr/share/man/man1. Type the full man path: "
	read MANPATH

	cp docs/man/* $MANPATH/ || die "Step 9 - copying man1 files to user specified path" 
	unset MANPATH
fi
	
if [ -d /usr/share/man/man8 ]; then
	cp docs/man/*.8 /usr/share/man/man8/ || die "Step 9 - copying man8 files" 
else
	echo " Man path not found in /usr/share/man/man8. Type the full man path: "
	read MANPATH

	cp docs/man/* $MANPATH/ || die "Step 9 - copying man8 files to user specified path" 
	unset MANPATH
fi
echo 
echo "Step 8 of 9 - Changing permissions and creating symbolic links"
chmod u+x $KOJONEY_PATH/kojoney.py || die "Step 10" 

echo " [+] Creating symlinks"
ln -s $KOJONEY_PATH/kojoney.py /usr/bin/kojoneyd || die "Step 8 - symlink for kononey.py"
ln -s $KOJONEY_PATH/kojreport /usr/bin/kojreport || die "Step 8 - symlink for kojreport"
ln -s $KOJONEY_PATH/kojreport-filter /usr/bin/kojreport-filter || die "Step 8 - symlink for kojreport-filter"
ln -s $KOJONEY_PATH/kip2country.py /usr/bin/kip2country || die "Step 8 - symlink for kip2country.py"
ln -s $KOJONEY_PATH/kojhumans /usr/bin/kojhumans || die "Step 8 - symlink for kojhumans"
ln -s $KOJONEY_PATH/kojsession /usr/bin/kojsession || die "Step 8 - symlink for kojsession"
ln -s $KOJONEY_PATH/sessions_with_commands /usr/bin/sessions_with_commands || die "Step 8 - symlink for sessions_with_commands"
ln -s $KOJONEY_PATH/commands_by_session_and_ip /usr/bin/commands_by_session_and_ip || die "Step 8 - symlink for commands_by_session_and_ip"
echo
echo "Step 9 of 9 - Final questions and fun"
echo

IS_CYGWIN=`uname -s | grep CYGWIN | grep -v grep | wc -l`

if [ $IS_CYGWIN -eq 0 ]; then
	echo -e "Do you want to run it automatically at boot time? (yes/no)"
	read res_sysv

	if [ $res_sysv != 'yes' ]; then
		echo -e "Skipping System V script installation"
	else
		cp init.d/* /etc/init.d/ || die "Step 9 - Init script installation failed"
		/sbin/chkconfig --level 345 kojoney on
	fi
else
	res_sysv='no'
fi

echo -e "Do you want to run it now? (yes/no)"
read res

if [ $res != 'yes' ]; then
	echo
	echo -e "Ok, you can run it by typing either '/usr/bin/kojoneyd' or '/etc/init.d/kojoney start'"
	echo
else
	echo "Starting daemon"

	if [ $res_sysv != 'yes' ]; then
		/usr/bin/kojoneyd >/dev/null &
	else
		/etc/init.d/kojoney start >/dev/null || die "Step 5" 
	fi
	echo
fi

echo -e "Be aware that by default Kojoney2 tries to listen "
echo -e "for connects on TCP port 22, if you have SSH installed "
echo -e "you're going to have to have it listen on a different "
echo -e "port, or modify /opt/kojoney/coret_config.py to have "
echo -e "Kojoney2 use a different port."
echo
echo -e "Kojoney2 installation finished!  Happy hunting!"
echo
