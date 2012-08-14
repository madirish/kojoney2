"""
    Kojoney - A honeypot that emules a secure shell (SSH) server.
    Copyright (C) 2005 Jose Antonio Coret

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""

import re

from coret_fake import *
from coret_log import *

from coret_command import *

import coret_std_unix


# Koret Honey ;)

uname_re = re.compile("uname(\ )*.*")
ls_re = re.compile("ls(\ )*.*")
su_re = re.compile("su(\ )*.*")
passwd_re = re.compile("passwd(\ )*.*")

denied_re = re.compile("""
(cat(\ )*.*)|(chgrp(\ )*.*)|(chmod(\ )*.*)|(chown(\ )*.*)|(cp(\ )*.*)|(cpio(\ )*.*)|(csh(\ )*.*)|(date(\ )*.*)|
(dd(\ )*.*)|(df(\ )*.*)|(ed(\ )*.*)|(echo(\ )*.*)|(grep(\ )*.*)|(false(\ )*.*)|(hostname(\ )*.*)|(kill(\ )*.*)|(ln(\ )*.*)|
(login(\ )*.*)|(mkdir(\ )*.*)|(mknod(\ )*.*)|(mktemp(\ )*.*)|(more(\ )*.*)|(cd(\ )*.*)|(mount(\ )*.*)|(more(\ )*.*)|
(mv(\ )*.*)|(ping(\ )*.*)|(ps(\ )*.*)|(rmdir(\ )*.*)|(sed(\ )*.*)|(sh(\ )*.*)|(bash(\ )*.*)|(tar(\ )*.*)|(su(\ )*.*)|(true(\ )*.*)|
(umount(\ )*.*)|(useradd(\ )*.*)|(grpadd(\ )*.*)""", re.VERBOSE)

def processCmd(data, transport):
    global FAKE_SHELL, FAKE_CWD, con

    retvalue = 1
    print "COMMAND IS : " + data
    transport.write('\r\n')

    #directory changing
    if re.match('^cd',data):
		directory = data.split()
		if len(directory) > 1:
			FAKE_CWD = directory[1]
		else:
			FAKE_CWD = "/"
	
    if uname_re.match(data):
        transport.write(FAKE_OS)
    elif data == "ps":
        for line in FAKE_PLAIN_PS:
            transport.write(line + '\r\n')
    elif re.match('^ps ', data):
	    for line in FAKE_PS:
			transport.write(line + '\r\n')
    elif data == "cat /etc/passwd":
        for line in FAKE_CAT_PASSWD:
            transport.write(line + '\r\n')
    elif data == "pwd":
	    #transport.write('/\r\n')
	    transport.write(FAKE_CWD + '\r\n')
    elif re.match('^cd',data):
	    pass

    #Removal of unnecessary functionality
    #Modified by Martin Barbella
    #elif data == "help":
        #transport.write('No soup for you!\r\n')
    #elif data == "bye":
        #transort.write('Goodbye\r\n')
    #elif re.match('fuck', data):
        #transport.write('Well fuck you too!')
        
    elif ls_re.match(data):
        if len(data.split()) > 1:
            input = data.split()
            dir_to_ls = input[1]
            #Fix for "cannot access [parameters]"
            #Added by Martin Barbella
            if(dir_to_ls[0] == '-'):
                if(len(input) > 2):
                    dir_to_ls = input[2]
                else:
                    dir_to_ls = FAKE_CWD
            if (dir_to_ls in FAKE_DIR_STRUCT):
                for line in FAKE_DIR_STRUCT[dir_to_ls]:
                    transport.write(line + '\r\n')
            else:
                 transport.write('ls: cannot access ' + dir_to_ls + ': No such file or directory\r\n')
        elif (FAKE_CWD in FAKE_DIR_STRUCT):
            for line in FAKE_DIR_STRUCT[FAKE_CWD]:
                transport.write(line + '\r\n')
        else:
            transport.write('ls: Error.\r\n')
    
    elif data == "uptime":
        transport.write(FAKE_UPTIME)
    elif data == "cat /proc/cpuinfo":
        for line in FAKE_CPUINFO:
            transport.write(line + '\r\n')
    elif data == "exit":
        transport.loseConnection()
    #Added by Martin Barbella
    elif data == "logout":
        transport.loseConnection()
    elif data == "w":
        for line in FAKE_W:
            transport.write(line + '\r\n')
    elif data == "who":
        transport.write(FAKE_USER)
    elif data == "ftp ..":
        for line in FAKE_FTP:
            transport.write(line + '\r\n')
    elif su_re.match(data):
        pass
    elif passwd_re.match(data):
        transport.write('geteuid: _getuid: Invalid operation')
    elif denied_re.match(data):
        #
        # Patch from Nicolas Surribas to fix bug 1463713
        #
        transport.write(FAKE_SHELL+ data.split(" ")[0] + ": " + FAKE_DENIED)
    else:
        if data == "":
            return 0

        result_data = ""
        try:
            result_data = executeCommand(data.split())
            
            if type(result_data) is bool:
                if not result_data:
                    transport.write(FAKE_SHELL + ": " + str(data.split()[0]) + ": command not found")
        except:
            print "Internal error:", data, ":",str(sys.exc_info()[1])
            transport.write(FAKE_SHELL + ": " + str(data.split()[0]) + ": command not found")
        
        data = ""

        if type(result_data) is not bool and result_data != "":
            transport.write(result_data)
            
        return retvalue
