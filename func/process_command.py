"""
    This file is part of the Kojoney2 honeypot

    Main Developer - Justin C. Klein Keane <jukeane@sas.upenn.edu>
    Original Developer - Jose Antonio Coret <joxeankoret@yahoo.es>

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

from lib.process_cmd import ProcessCmd

def process_command(data, transport, attacker_username, ip, fake_workingdir):
    #each command proccessor function takes care of printing its own ending linebreaks
    #printlinebreak is not used in ProcessCmd
    printlinebreak = 0
    cmd = ''
    params = ''
    data = data.strip()
    print "COMMAND IS : " + data
    transport.write('\r\n')
    data=data.split()
    if len(data)>0:
        cmd = data[0]
    if len(data)>1:
        params=data[1:len(data)]
    cmd_processor = ProcessCmd(cmd, params, transport, attacker_username, ip, fake_workingdir)
    (fake_workingdir, attacker_username) = cmd_processor.get_values()
    # return some values so they remain dynamic        
    return (printlinebreak, fake_workingdir, attacker_username)
