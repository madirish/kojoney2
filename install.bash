#!/bin/bash

function die
{
	echo Error at $1
	echo Kojoney installation failed
	#exit 1
}

KOJONEY_PATH=/usr/share/kojoney
INSTALLER_VERSION=0.4

echo Kojoney Honeypot installer. 
echo
echo Kojoney is bound by a number of license agreements
echo which are included in the install path.
echo
#echo "Press enter to view the license agreement(s) ..."
#read
#more LICENSE libs/license.zop libs/twisted.license 2>/dev/null || less LICENSE libs/license.zop libs/twisted.license 

echo -e "Do you accept the ZPL, MIT and GPL license terms (yes/no) ?"
read license_accept

#
# Bug 1463831
#
#if [ "$license_accept" = 'yes' ]; then
#
if [ "$license_accept" = 'yes' ]; then
	echo All licenses accepted
	echo
	clear
	echo "******************************************"
	echo " Kojoney Honeypot Installer version $INSTALLER_VERSION "
	echo "******************************************"
	echo
else
	echo You need to accept ALL the licenses to install it.
	echo Exiting...
	echo
	exit
fi

NEED_DATABASE="unspecified"
while [ $NEED_DATABASE == 'unspecified' ]
do
	echo -e "Do you need to create a database for Kojoney? (yes/no)"
	read create_db
	if [[ $create_db == 'yes' || $create_db == 'no' ]]; then
		NEED_DATABASE="specified"
	fi
done

if [ $create_db == 'yes' ]; then
	echo We will now create the Kojoney database.  The credentials used to create the
	echo database are stored in coret_config.py and can be changed at a later time if
	echo necessary.  By default the database will be called kojoney.
	echo
	echo Please enter the MySQL username that can create the kojoney database and tables:
	read mysql_user
	echo Please enter the MySQL password for this user:
	read mysql_password
	echo -e "Please enter the MySQL database server (i.e. localhost)"
	read mysql_host
	if [ ! /usr/bin/mysql -u $mysql_user -p$mysql_root_pw -h $mysql_host < create_tables.sql ]; then
		echo Error creating database.  Please create it manually using create_tables.sql.
		echo Installer exiting...
		exit
	fi 
fi

echo "$create_db"
exit;



if [ -d $KOJONEY_PATH ]; then
	echo Directory exists. Uninstall it first.
	echo Exiting...
	exit
else
	mkdir $KOJONEY_PATH
fi

if [ -d /etc/kojoney ]; then
	echo -e "WARNING! Directory /etc/kojoney exists!"
else
	mkdir /etc/kojoney
fi

echo "Step 1 - Copying files"
cp *.py* $KOJONEY_PATH
cp fake_users /etc/kojoney
cp -f reports/* $KOJONEY_PATH 2>/dev/null
temp_dir=`mktemp -d`
echo " [+] Working on temp directory $temp_dir"
echo " [+] Copying base libraries"
cp -f libs/* $temp_dir 
echo " [+] Copying optional libraries"
cp -f reports/ip_country/* $temp_dir

old_dir=`pwd`
cd $temp_dir

echo " [+] Extracting libraries in temporary directory"
find . -name "*.tar.gz" -exec tar -xzf {} ';' > /dev/null

echo "Step 2 - Building libraries"
echo " [+] Building and installing [IP-Country]"
cd IP*

perl Makefile.PL > /dev/null || die "Step 2" 
make > /dev/null || die "Step 2" 
make install > /dev/null || die "Step 2" 

cd $temp_dir
cd G*

echo " [+] Building and installing [Geography-Countries]"
perl Makefile.PL > /dev/null || die "Step 2" 
make > /dev/null || die "Step 2" 
make install > /dev/null || die "Step 2" 

cd $temp_dir
cd Zope*

echo " [+] Building and installing [Zope Interfaces]"
python setup.py build > /dev/null || die "Step 2" 
python setup.py install > /dev/null || die "Step 2" 

cd $temp_dir
cd pycrypto*

echo " [+] Building and installing [PyCrypto]"
python setup.py build > /dev/null || die "Step 2" 
python setup.py install > /dev/null || die "Step 2" 

cd $temp_dir
cd MySQL*

echo " [+] Building and installing [MySQL-python]"
python setup.py build > /dev/null || die "Step 2" 
python setup.py install > /dev/null || die "Step 2" 

cd $temp_dir
cd Twisted-*

echo " [+] Building and installing [Twisted extension]"
python setup.py build > /dev/null || die "Step 2" 
python setup.py install > /dev/null || die "Step 2" 

cd $old_dir
rm -fr $temp_dir

echo "Step 3 - Installing documentation "
echo " [+] Installing man pages"

if [ -d /usr/share/man/man1 ]; then
	cp docs/man/* /usr/share/man/man1/ || die "Step 3" 
else
	echo " Man path not found in /usr/share/man/man1. Type the full man path: "
	read MANPATH

	cp docs/man/* $MANPATH/ || die "Step 3" 
	unset MANPATH
fi

echo "Step 4 - Changing permissions and creating symbolic links"
chmod u+x $KOJONEY_PATH/kojoney.py || die "Step 4" 

echo " [+] Creating symlinks"
ln -s $KOJONEY_PATH/kojoney.py /usr/bin/kojoneyd || die "Step 4" 
ln -s $KOJONEY_PATH/kojreport /usr/bin/kojreport || die "Step 4" 
ln -s $KOJONEY_PATH/kojreport-filter /usr/bin/kojreport-filter || die "Step 4" 
ln -s $KOJONEY_PATH/kip2country /usr/bin/kip2country || die "Step 4" 
ln -s $KOJONEY_PATH/kojhumans /usr/bin/kojhumans || die "Step 4" 
ln -s $KOJONEY_PATH/kojsession /usr/bin/kojsession || die "Step 4" 
ln -s $KOJONEY_PATH/sessions_with_commands /usr/bin/sessions_with_commands || die "Step 4"
ln -s $KOJONEY_PATH/commands_by_session_and_ip /usr/bin/commands_by_session_and_ip || die "Step 4"
echo

echo " [+] Creating directory for url archives"
mkdir /var/log/kojoney

echo "Step 5 - Final questions and fun"
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
echo "Kojoney installation finished."
echo
