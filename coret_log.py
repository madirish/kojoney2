import os
import sys

from coret_config import *

from twisted.python import log

def msg(data):
    print "Intercepted log message"
    twisted.python.log.msg(data)

def log_machine(data):
    print "Log_machine: " + data
    pass

def log_cmd_session(session, data):
    print "Log_cmd_session: " + session + " :: " + data
    pass

def start_logging():
    if os.getuid() == 0:
        log_file_list = ROOT_CONFIG_LOGS
    else:
        log_file_list = CONFIG_LOGS

    for log_file in log_file_list:
        print "Ok, starting log to "  + str(log_file)
        log.startLogging(log_file)
