"""
    Modified by Justin C. Klein Keane <justin@madirish.net>
    Last modified: April 26, 2012
    
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
(dd(\ )*.*)|(df(\ )*.*)|(ed(\ )*.*)|(echo(\ )*.*)|(grep(\ )*.*)|(false(\ )*.*)|(kill(\ )*.*)|(ln(\ )*.*)|
(login(\ )*.*)|(mkdir(\ )*.*)|(mknod(\ )*.*)|(mktemp(\ )*.*)|(more(\ )*.*)|(mount(\ )*.*)|(more(\ )*.*)|
(mv(\ )*.*)|(ping(\ )*.*)|(rmdir(\ )*.*)|(sed(\ )*.*)|(sh(\ )*.*)|(bash(\ )*.*)|(su(\ )*.*)|(true(\ )*.*)|
(umount(\ )*.*)|(useradd(\ )*.*)|(grpadd(\ )*.*)""", re.VERBOSE)

def processCmd(data, transport, attacker_username, ip):
    global FAKE_SHELL, FAKE_CWD, con
    
    retvalue = 1
    print "COMMAND IS : " + data
    transport.write('\r\n')

    #directory changing
    if re.match('^cd',data):
        directory = data.split()
        
        if directory[1] == "/root": 
            if attacker_username != "root":
                transport.write('-bash: cd: /root: Permission denied')
                FAKE_CWD = "/"
        elif len(directory) > 1:
            FAKE_CWD = directory[1]
        else:
            FAKE_CWD = "/"
    
    if uname_re.match(data):
        transport.write(FAKE_OS)
    elif data == "ps":
        for line in FAKE_PLAIN_PS:
            transport.write(line + '\r\n')
    elif re.match('^unset ', data):
        pass
    elif re.match('^date', data):
        transport.write(TIMESTAMP)
    elif re.match('^whoami', data):
        transport.write(attacker_username)
    elif re.match('^hostname', data):
        transport.write(FQDN)
    elif re.match('^ps ', data):
        for line in FAKE_PS:
            transport.write(line + '\r\n')
    elif data == "cat /etc/passwd":
        for line in FAKE_CAT_PASSWD:
            transport.write(line + '\r\n')
    elif data == "cat /etc/issue":
        for line in FAKE_ETC_ISSUE:
            transport.write(line + '\r\n')
    elif data == "pwd":
        transport.write(FAKE_CWD + '\r\n')
    elif re.match('^cd',data):
        pass
    elif re.match('^tar', data):
            transport.write("tar: You must specify one of the `-Acdtrux' or `--test-label'  options\r\n")
            transport.write("Try `tar --help' or `tar --usage' for more information.\r\n")
    elif re.match('^history', data):
            pass
    elif re.match('^export', data):
            pass
    elif re.match('^gcc', data):
            transport.write('gcc: no input files\r\n')
    elif re.match('^make', data):
            transport.write('make: *** No targets specified and no makefile found.  Stop.\r\n')
    elif re.match('^perl', data):
            transport.write('This is perl 5, version 12, subversion 4 (v5.12.4) ')
            transport.write('built for i386-linux-thread-multi\r\n\r\n')
            transport.write('Copyright 1987-2010, Larry Wall\r\n\r\n')
            transport.write('Perl may be copied only under the terms of either the')
            transport.write('Artistic License or the\r\nGNU General Public License, ')
            transport.write('which may be found in the Perl 5 source kit.\r\n\r\n')
            transport.write('Complete documentation for Perl, including FAQ lists, ')
            transport.write('should be found on\r\nthis system using "man perl" or ')
            transport.write('"perldoc perl".  If you have access to the\r\nInternet, ')
            transport.write( 'point your browser at http://www.perl.org/, the Perl Home Page.\r\n')
    elif re.match('^passwd', data):
            transport.write('Changing password for user.\r\n')
            return 'New password: '

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
                 transport.write('ls: cannot access ' + dir_to_ls + ': No such file or directory')
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
    elif data == "id":
        if attacker_username == "root":
            transport.write('uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)')
        else:
            transport.write('uid=501('+attacker_username+') gid=502('+attacker_username+') groups=100(users)')
    elif data == "w":
        transport.write('USER\tTTY\tFROM\tLOGIN@\t\tIDLE\tJCPU\tPCPU\tWHAT\r\n')
        transport.write(attacker_username + '\tpts/1\t'+ip+'\t09:05\t0.00s\t0.04s\t0.00s\tw')
    elif data == "who":
        transport.write(attacker_username + '\tpts/1')
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
