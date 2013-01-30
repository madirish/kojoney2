"""
    This file is part of the Kojoney2 honeypot

    Main Developer - Justin C. Klein Keane <jukeane@sas.upenn.edu>
    Original Developer - Jose Antonio Coret <joxeankoret@yahoo.es>
    Last updated 28 January 2013

    This file processes user supplied input, parsing the commands 
    and then returning a "fake" response.

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


denied_re = re.compile("""
(cat(\ )*.*)|(chgrp(\ )*.*)|(chmod(\ )*.*)|(chown(\ )*.*)|(cp(\ )*.*)|(cpio(\ )*.*)|(csh(\ )*.*)|(date(\ )*.*)|
(dd(\ )*.*)|(df(\ )*.*)|(ed(\ )*.*)|(echo(\ )*.*)|(grep(\ )*.*)|(false(\ )*.*)|(kill(\ )*.*)|(ln(\ )*.*)|
(login(\ )*.*)|(mknod(\ )*.*)|(mktemp(\ )*.*)|(more(\ )*.*)|(mount(\ )*.*)|(more(\ )*.*)|
(mv(\ )*.*)|(ping(\ )*.*)|(rmdir(\ )*.*)|(sed(\ )*.*)|(sh(\ )*.*)|(bash(\ )*.*)|(su(\ )*.*)|(true(\ )*.*)|
(umount(\ )*.*)|(useradd(\ )*.*)|(grpadd(\ )*.*)""", re.VERBOSE)

def processCmd(data, transport, attacker_username, ip, fake_workingdir):
    global FAKE_SHELL, con, FAKE_USERNAME

    printlinebreak = 0
    data = data.strip()
    print "COMMAND IS : " + data
    transport.write('\r\n')

    #directory changing
    if re.match('^cd',data):
        directory = data.split()
        if len(directory) == 1:
            if attacker_username in FAKE_HOMEDIRS:
                fake_workingdir = FAKE_HOMEDIRS[attacker_username]
            else:
                fake_workingdir = "/"
        else:
            if directory[1] == "/root": 
                if attacker_username != "root":
                    transport.write('-bash: cd: /root: Permission denied')
                    fake_workingdir = "/"
            elif len(directory) > 1:
                # Descending (cd foo) or absolute (cd /foo)
                old_dir = fake_workingdir
                if directory[1][0:1] == '/':
                    fake_workingdir = directory[1]
                else:
                    fake_workingdir += '/' + directory[1]
                if fake_workingdir not in FAKE_DIR_STRUCT:
                    transport.write('-bash: cd: ' + directory[1] + ': No such file or directory')
                    fake_workingdir = old_dir
            else:
                fake_workingdir = "/"
    #apachectl
    elif data == "apachectl status":
        transport.write('Not Found\r\n\r\n')
        transport.write('The requested URL /server-status was not found on this server.\r\n\r\n')
        transport.write(' --------------------------------------------------------------------------\r\n\r\n')
        transport.write('Apache/2.2.15 (CentOS) Server at localhost Port 80\r\n')
    #cat /etc/passwd
    elif data == "cat /etc/passwd":
        for line in FAKE_CAT_PASSWD:
            transport.write(line + '\r\n')
    #cat /etc/issue
    elif data == "cat /etc/issue":
        for line in FAKE_ETC_ISSUE:
            transport.write(line + '\r\n')
    #cat /proc/cpuinfo
    elif data == "cat /proc/cpuinfo":
        for line in FAKE_CPUINFO:
            transport.write(line + '\r\n')
    #curl
    elif re.match('curl', data):
        result_data = executeCommand(data.split(), ip)
        if type(result_data) is not bool and result_data != "":
            printlinebreak = 1
            transport.write(result_data)
    #date
    elif re.match('^date', data):
        transport.write(TIMESTAMP)
        printlinebreak = 1
    #exit
    elif data == "exit":
        transport.loseConnection()
    #export
    elif re.match('^export', data):
            pass
    #gcc
    elif re.match('^gcc', data):
            transport.write('gcc: no input files\r\n')
    #history
    elif re.match('^history', data):
            pass
    #hostname
    elif re.match('^hostname', data):
        transport.write(FQDN)
    #id
    elif data == "id":
        printlinebreak = 1
        if attacker_username == "root":
            transport.write('uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)')
        else:
            transport.write('uid=501('+attacker_username+') gid=502('+attacker_username+') groups=100(users)')
    #ifconfig
    elif re.match('^ifconfig', data):
        for line in FAKE_IFCONFIG:
            transport.write(line + '\r\n')
    #logout - Added by Martin Barbella
    elif data == "logout":
        transport.loseConnection()
    #ls
    elif re.match("ls(\ )*.*", data):
        printlinebreak = 1
        if len(data.split()) > 1:
            input = data.split()
            dir_to_ls = input[1]
            #Fix for "cannot access [parameters]"
            #Added by Martin Barbella
            if(dir_to_ls[0] == '-'):
                if(len(input) > 2):
                    dir_to_ls = input[2]
                else:
                    dir_to_ls = fake_workingdir
            if (dir_to_ls in FAKE_DIR_STRUCT):
                for line in FAKE_DIR_STRUCT[dir_to_ls]:
                    if (line == FAKE_DIR_STRUCT[dir_to_ls][-1]):
                        transport.write(line)
                    else:
                        transport.write(line + '\r\n')
            else:
                 transport.write('ls: cannot access ' + dir_to_ls + ': No such file or directory')
        elif (fake_workingdir in FAKE_DIR_STRUCT):
            for line in FAKE_DIR_STRUCT[fake_workingdir]:
                if (line == FAKE_DIR_STRUCT[fake_workingdir][-1]):
                    transport.write(line)
                else:
                    transport.write(line + '\r\n')
        else:
            transport.write('ls: Error.\r\n')
    #make
    elif re.match('^make', data):
            transport.write('make: *** No targets specified and no makefile found.  Stop.\r\n')
    #mkdir
    elif re.match('^mkdir',data):
        directory = data.split()
        if len(directory) == 1:
            transport.write("mkdir: missing operand\r\nTry `mkdir --help' for more information.")
        else:
            print 'Appending directory ' + directory[1]
            #format the new entry
            newdirectory = 'drwx--x--x 70 ' + attacker_username + '     users 4.0K ' + datetime.now().strftime("%Y-%m-%d %H:%M ") + directory[1] + '/'
            FAKE_DIR_STRUCT[fake_workingdir].append(newdirectory)
            FAKE_DIR_STRUCT[fake_workingdir + '/' + directory[1]] = ""
    #netstat
    elif re.match('^netstat', data):
        for line in FAKE_NETSTAT:
            transport.write(line + '\r\n')
    #passwd
    elif re.match('^passwd', data):
            printlinebreak = 1
            transport.write('Changing password for user.\r\n')
            transport.write('New password: ')
    #perl
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
    #ps
    elif re.match('^ps ', data):
        for line in FAKE_PS:
            transport.write(line + '\r\n')
    #pwd
    elif data == "pwd":
        transport.write(fake_workingdir + '\r\n')
    #rpm
    elif re.match("rpm(\ )*.*", data):
        transport.write('RPM version 4.8.0\r\n')
        transport.write('Copyright (C) 1998-2002 - Red Hat, Inc.\r\n')
        transport.write('This program may be freely redistributed under the terms of the GNU GPL\r\n')
    #service
    elif re.match("^(/sbin/)service", data):
        servicecmd = data.split(" ")
        printlinebreak = 1
        if (len(servicecmd)) == 3:
            if servicecmd[1] in FAKE_SERVICES:
                if servicecmd[2] == "start":
                    transport.write('Starting ' + servicecmd[1] + ":")
                elif servicecmd[2] == "stop":
                    transport.write('Stopping ' + servicecmd[1] + ":")
                elif servicecmd[2] == "restart":
                    transport.write('Restarting ' + servicecmd[1] + ":")
                elif servicecmd[2] == "status":
                    transport.write(servicecmd[1] + " dead but subsys locked")
                else:
                    transport.write(FAKE_SERVICE_USAGE.format(servicecmd[1]))
            else:
                transport.write(servicecmd[1] + ': unrecognized service')
        elif (len(servicecmd)) == 2:
            if servicecmd[1] == "--status-all":
                for line in FAKE_SERVICE_ALL:
                    transport.write(line + '\r\n')
            elif servicecmd[1] in FAKE_SERVICES:
                transport.write('Usage: ' + servicecmd[1] + ': {start|stop|restart}')
            else:
                transport.write(servicecmd[1] + ': unrecognized service')
        else:
            transport.write('Usage: service < option > | --status-all | [ service_name [ command | --full-restart ] ]')
        
    #su and sudo
    elif re.match("su(\ )*.*", data):
        if data == "sudo su" or data == "su":
            attacker_username = 'root'
        else:
            switchtouser = data.split()[1]
            print "Attempting to su to " + switchtouser
            if switchtouser in FAKE_HOMEDIRS:
                attacker_username = switchtouser
                print 'Changing FAKE_USERNAME to ' + switchtouser
            else:
                printlinebreak = 1
                transport.write('Unknown user: ' + switchtouser)
    #tar
    elif re.match('^tar', data):
            transport.write("tar: You must specify one of the `-Acdtrux' or `--test-label'  options\r\n")
            transport.write("Try `tar --help' or `tar --usage' for more information.\r\n")
    #uname
    elif re.match("uname(\ )*.*", data):
        printlinebreak = 1
        transport.write(FAKE_OS)
    #unset
    elif re.match('^unset ', data):
        pass
    #uptime
    elif data == "uptime":
        transport.write(FAKE_UPTIME)
        printlinebreak = 1
    #w
    elif data == "w":
        printlinebreak = 1
        transport.write('USER\tTTY\tFROM\tLOGIN@\t\tIDLE\tJCPU\tPCPU\tWHAT\r\n')
        transport.write(attacker_username + '\tpts/1\t'+ip+'\t09:05\t0.00s\t0.04s\t0.00s\tw')
    #wget
    elif re.match('wget', data):
        result_data = executeCommand(data.split(), ip)
        if type(result_data) is not bool and result_data != "":
            printlinebreak = 1
            transport.write(result_data)
    #who
    elif data == "who":
        transport.write(attacker_username + '\tpts/1')
        printlinebreak = 1
    #whoami
    elif re.match('^whoami', data):
        transport.write(attacker_username)
        printlinebreak = 1
    #yum
    elif re.match('^yum(\ )*.*', data):
        if re.match('^yum install', data):
            transport.write('Another app is currently holding the yum lock; waiting for it to exit...\r\n')
        else:
            transport.write('Loaded plugins: fastestmirror\r\n')
            transport.write('You need to give some command\r\n')
            transport.write('Usage: yum [options] COMMAND\r\n')
    # Fall through to anything else we haven't predefined
    elif denied_re.match(data):
        #
        # Patch from Nicolas Surribas to fix bug 1463713
        #
        transport.write(FAKE_SHELL+ data.split(" ")[0] + ": " + FAKE_DENIED)
        printlinebreak = 1
    else:
        print "Potentially unknown command"
        if data == "":
            pass
        else:
            printlinebreak = 1
            if len(data.split()) > 1:
                transport.write(FAKE_SHELL + ": " + data.split()[0] + ": command not found")
            else:
                transport.write(FAKE_SHELL + ": " + data + ": command not found")
    # return some values so they remain dynamic        
    return (printlinebreak, fake_workingdir, attacker_username)
