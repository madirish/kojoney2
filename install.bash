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

KOJONEY_PATH=/opt/kojoney

clear
echo "******************************************"
echo " Kojoney2 Honeypot Installer "
echo "******************************************"
echo "by Justin C. Klein Keane <justin@madirish.net>"
echo based on Kojoney, by Jose Antonio Coret
echo 
echo Step 1 of 11 - Checking for prerequisite dependencies...

# Do prerequisites for RedHat systems
if [ -e /etc/redhat-release ]; then
	if rpm -q python-devel | grep not ; then
		echo " [+] Python development libraries and C headers are not installed!"
		yum install python-devel
	fi
	if [ ! -e /usr/bin/gcc ]; then
		echo " [+] GNU C compiler is not installed!"
		yum install gcc
	fi
	if rpm -q mysql-devel | grep not ; then
	  echo " [+] MySQL development libraries and C headers are not installed!"
	  yum install mysql-devel
	fi
	if rpm -q logrotate | grep not ; then
	  echo " [+] Logrotate not installed!"
	  yum install logrotate
	fi
	# Install the Python libraries
	if rpm -q MySQL-python | grep not ; then
		echo " [+] Python MySQL library not installed!"
		yum install MySQL-python
	fi
	if rpm -q python-crypto | grep not ; then
	  echo Python crypto library not installed!
	  yum install python-crypt
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
echo Step 2 of 11 - Licenses
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
echo "Step 3 of 11 - Creating directory structure"
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

echo " [+] Installed at $KOJONEY_PATH"
echo 
echo "Step 4 of 11 - Database configuration"
NEED_DATABASE="unspecified"
while [ $NEED_DATABASE == 'unspecified' ]
do
	echo -e "Do you need to create a MySQL database for Kojoney? (yes/no)"
	read create_db
	if [[ $create_db == 'yes' || $create_db == 'no' ]]; then
		NEED_DATABASE="specified"
	fi
done

if [ $create_db == 'yes' ]; then
	echo We will now create the Kojoney2 database.  The credentials used to create the
	echo database are stored in coret_config.py and can be changed at a later time if
	echo necessary.  By default the database will be called kojoney.
	echo
	echo Please enter the MySQL username that can create the kojoney database and tables:
	read mysql_user
	echo Please enter the MySQL password for this user:
	read mysql_password
	echo -e "Please enter the MySQL database server (i.e. localhost)"
	read mysql_host
	/usr/bin/mysql -u $mysql_user --password=$mysql_password -h $mysql_host < create_tables.sql
	
	echo Updating the config file...
	# Replace tokens with user specified values
	sed -i "s/db_user/$mysql_user/g" coret_config.py
	sed -i "s/db_password/$mysql_password/g" coret_config.py
	sed -i "s/db_host/$mysql_host/g" coret_config.py
fi
echo 
echo "Step 5 of 11 - Email reporting configuration"
# Daily reports
echo -e "Would you like daily reports e-mailed? (yes/no)"
read want_reports
if [ $want_reports == 'yes' ]; then
	echo -e "Please enter e-mail of desired recipient:"
	read email_to
	sed -i "s/root\@localhost/$email_to/g" reports/mailalert.bash
	if ! cat /etc/crontab | grep mailalert ; then
		echo "  59  23  *  *  * root $KOJONEY_PATH/mailalert.bash > /dev/null" >> /etc/crontab
		echo " [+] Cron for report e-mail scheduled in /etc/crontab"
	fi
fi
echo 
echo "Step 6 of 11 - Housekeeping configuration"
# Assume logrotate is installed
touch /etc/logrotate.d/kojoney
echo "/var/log/honeypot.log {" > /etc/logrotate.d/kojoney
echo "    sharedscripts" >> /etc/logrotate.d/kojoney
echo "    daily" >> /etc/logrotate.d/kojoney
echo "    endscript" >> /etc/logrotate.d/kojoney
echo "}" >> /etc/logrotate.d/kojoney
echo " [+] Logrotate scheduled"
echo 
echo "Step 7 of 11 - Honeypot customization"
# Customize honeypot
echo Please enter the fully qualified hostname for your honeypot:
read user_fqdn
sed -i "s/fqdn_placeholder/$user_fqdn/g" coret_fake.py
echo 
echo "Step 8 of 11 - Copying files"
cp *.py* $KOJONEY_PATH
cp fake_users $KOJONEY_PATH/etc/
cp -f reports/* $KOJONEY_PATH 2>/dev/null
echo " [+] Kojoney files installed
echo 
echo "Step 9 of 11 - Installing documentation "
echo " [+] Installing man pages"

if [ -d /usr/share/man/man1 ]; then
	cp docs/man/*.1 /usr/share/man/man1/ || die "Step 3 - copying man1 files" 
else
	echo " Man path not found in /usr/share/man/man1. Type the full man path: "
	read MANPATH

	cp docs/man/* $MANPATH/ || die "Step 3 - copying man1 files to user specified path" 
	unset MANPATH
fi
	
if [ -d /usr/share/man/man8 ]; then
	cp docs/man/*.8 /usr/share/man/man8/ || die "Step 3 - copying man8 files" 
else
	echo " Man path not found in /usr/share/man/man8. Type the full man path: "
	read MANPATH

	cp docs/man/* $MANPATH/ || die "Step 3 - copying man8 files to user specified path" 
	unset MANPATH
fi
echo 
echo "Step 10 of 11 - Changing permissions and creating symbolic links"
chmod u+x $KOJONEY_PATH/kojoney.py || die "Step 4" 

echo " [+] Creating symlinks"
ln -s $KOJONEY_PATH/kojoney.py /usr/bin/kojoneyd || die "Step 4 - symlink for kononey.py" 
ln -s $KOJONEY_PATH/kojreport /usr/bin/kojreport || die "Step 4 - symlink for kojreport" 
ln -s $KOJONEY_PATH/kojreport-filter /usr/bin/kojreport-filter || die "Step 4 - symlink for kojreport-filter" 
ln -s $KOJONEY_PATH/kip2country.py /usr/bin/kip2country || die "Step 4 - symlink for kip2country.py" 
ln -s $KOJONEY_PATH/kojhumans /usr/bin/kojhumans || die "Step 4 - symlink for kojhumans" 
ln -s $KOJONEY_PATH/kojsession /usr/bin/kojsession || die "Step 4 - symlink for kojsession" 
ln -s $KOJONEY_PATH/sessions_with_commands /usr/bin/sessions_with_commands || die "Step 4 - symlink for sessions_with_commands"
ln -s $KOJONEY_PATH/commands_by_session_and_ip /usr/bin/commands_by_session_and_ip || die "Step 4 - symlink for commands_by_session_and_ip"
echo
echo "Step 11 of 11 - Final questions and fun"
echo

IS_CYGWIN=`uname -s | grep CYGWIN | grep -v grep | wc -l`

if [ $IS_CYGWIN -eq 0 ]; then
	echo "Do you want to run it automatically at boot time (yes/no)? "
	read res_sysv

	if [ $res_sysv != 'yes' ]; then
		echo "Skipping System V script installation"
	else
		cp init.d/* /etc/init.d/ || die "Step 5" 
		echo 
		echo "***No run levels were assigned. You need to do this manually.***"
		echo
	fi
else
	res_sysv='no'
fi

echo "Do you want to run it now (yes/no)? "
read res

if [ $res != 'yes' ]; then
	echo
	echo "Ok, you can run it by typing either '/usr/bin/kojoneyd' or '/etc/init.d/kojoney start'"
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

echo
echo "Kojoney2 installation finished!  Happy hunting!"
echo
