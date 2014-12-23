import os
import sys
from kojoney_config import LOG_LOCATION

if os.getuid() == 0:
    ROOT_CONFIG_LOGS = [sys.stderr, open(LOG_LOCATION, "a")]
else:
    CONFIG_LOGS = [sys.stderr, open(LOG_LOCATION, "a")]