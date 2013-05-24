"""
    This file is part of the Kojoney2 honeypot

    Main Developer - Justin C. Klein Keane <jukeane@sas.upenn.edu>
    Original Developer - Jose Antonio Coret <joxeankoret@yahoo.es>
    Last updated 28 January 2013

    Kojoney2 - A honeypot that emulates a secure shell (SSH) server.

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
import coret_std_unix

def executeCommand(cmdLine, ip):
    """ 
    Wrapper method for supporting actual commands run on the honeypot
    """
    command = cmdLine[0]

    if command == "wget":
        return coret_std_unix.wget(cmdLine, ip)
    elif command == "curl":
        return coret_std_unix.curl(cmdLine, ip)
    else:
        return False
