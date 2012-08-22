import os
import sys

from coret_config import *

from twisted.python import log

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
        log.FileLogObserver.emit=koj_watcher
    
def koj_watcher(self,eventDict):
  """Custom emit for FileLogObserver"""
  text = log.textFromEventDict(eventDict)
  if text is None:
    return
  self.timeFormat='[%Y-%m-%d %H:%M:%S]'
  timeStr = self.formatTime(eventDict['time'])
  fmtDict = {'text': text.replace("\n", "\n\t")}
  msgStr = log._safeFormat("%(text)s\n", fmtDict)
  print "::: " + msgStr

