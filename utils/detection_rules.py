"""
This file defines the key signs we're looking for in order to detect a SYN attack once our systems are overflowed
"""

PORT_SCAN_THRESHOLD = 20 #number of ports
TIME_WINDOW = 60 #seconds
SYN_THRESHHOLD = 100 #excessive SYN packets