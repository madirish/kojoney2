import sys
import urllib
import random

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
