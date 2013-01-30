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
import urllib
import random
import hashlib

from coret_config import DOWNLOAD_REAL_FILE, DOWNLOAD_REAL_DIR

def getGoodFilename(filename):
    
    buf = ""
    
    for c in filename:
        if c.isalnum():
            buf += c
        else:
            buf += "_"
    
    return(buf + str(random.randint(0, 999)))

def downloadFileTo(url, directory):
    try:
        
        if url.find("://") == -1:
            url = "http://" + url

        data = urllib.urlopen(url)
        data = data.read()
        
        filename = getGoodFilename(url)
        
        
        f = open(directory + filename, "wb")
        f.write(data)
        f.close()
        
        # Check the MD5sum against the database
        checksum = hashlib.md5()
        checksum.update(data)
        filemd5 = checksum.digest()
        print "The file md5 is " + filemd5
        
        # Delete duplicate files or ClamAV new ones
        
        # Record the download in the database

        print "Saved the file",directory + filename,"requested by the attacker."
    except:
        print "Error downloading file",url,"request by attacker.",sys.exc_info()[1]

def wget(params):

    i = 0

    data = ""

    if len(params) == 1:
        data  = "wget: You need to specify the URL\r\n"
        data +="\r\n"
        data +="Usage: wget [OPTIONS] [URL]\r\n"
        data +="\r\n"
        data +="Use wget --help to read the complete option list.\r\n"
        
        return data

    for param in params:
        if i == 0:
            i += 1
            continue

        if not param.startswith("-"):
            
            if DOWNLOAD_REAL_FILE:
                downloadFileTo(param, DOWNLOAD_REAL_DIR)
            
            data = "Downloading URL ", str(param)
            return "wget: Unknown error"

    return data

def curl(params):

    i = 0

    data = ""

    if len(params) == 1:
        data  = "curl: try 'curl --help' or 'curl --manual' for more information\r\n"
        
        return data

    for param in params:
        if i == 0:
            i += 1
            continue

        if not param.startswith("-"):
            
            if DOWNLOAD_REAL_FILE:
                downloadFileTo(param, DOWNLOAD_REAL_DIR)

            data = "Downloading URL ", str(param)
            return "curl: Unknown error"

    return data
