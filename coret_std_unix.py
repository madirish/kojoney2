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
import sys
import subprocess
import urllib
import random
import hashlib

from honeypot_db import HoneypotDB
from coret_config import DOWNLOAD_REAL_FILE, DOWNLOAD_REAL_DIR, SENSOR_ID
from coret_config import DATABASE_HOST, DATABASE_USER, DATABASE_PASS, DATABASE_NAME, WHITELIST

def getGoodFilename(filename):
    
    buf = ""
    
    for c in filename:
        if c.isalnum():
            buf += c
        else:
            buf += "_"
    
    return(buf + str(random.randint(0, 999)))

def downloadFileTo(url, directory, ip):
    print "Attempting download of " + url
    try:
        if url.find("://") == -1:
            url = "http://" + url
        data = urllib.urlopen(url)
        data = data.read()
        filename = getGoodFilename(url)

        # Todo: Don't write file if it's a duplicate!
        f = open(directory + filename, "wb")
        f.write(data)
        f.close()
        
        # Determine the filetype
        try:
            output = subprocess.Popen(['/usr/bin/file', directory + filename],
                                      stdout=subprocess.PIPE).communicate()[0]
            filetype = output.split(': ')[1]
        except:
            filetype = "Error retrieving filetype"
        
        # Check the MD5sum against the database
        checksum = hashlib.md5()
        checksum.update(data)
        filemd5 = checksum.hexdigest()
        
        # Log the download
        HoneypotDB().log_download(ip, url, filemd5, filename, filetype, SENSOR_ID)
    except:
        print "Error downloading file",url,"request by attacker: ",sys.exc_info()[1]

def wget(params, ip):
    data = ""
    print "Attempting wget with " + ', '.join(params)

    if len(params) == 0:
        data  = "wget: You need to specify the URL\r\n"
        data +="\r\n"
        data +="Usage: wget [OPTIONS] [URL]\r\n"
        data +="\r\n"
        data +="Use wget --help to read the complete option list.\r\n"

    for param in params:
        if not param.startswith("-"):
            
            if DOWNLOAD_REAL_FILE:
                downloadFileTo(param, DOWNLOAD_REAL_DIR, ip)
            
            data = "Downloading URL " + str(' '.join(params))
            data += "\r\nwget: Unknown error"

    return data

def curl(params, ip):
    data = ""

    if len(params) == 0:
        data  = "curl: try 'curl --help' or 'curl --manual' for more information\r\n"

    for param in params:
        if not param.startswith("-"):
            if DOWNLOAD_REAL_FILE:
                downloadFileTo(param, DOWNLOAD_REAL_DIR, ip)

            data = "Downloading URL " + str(' '.join(params))
            return data + "\r\ncurl: Unknown error"

    return data
