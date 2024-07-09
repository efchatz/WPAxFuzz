import subprocess
from Mngmt_frames.Beacon import Beacon
from Mngmt_frames.AssoReq import AssoReq
from Mngmt_frames.AssoResp import AssoResp
from Mngmt_frames.Authentication import Authentication
from Mngmt_frames.Probe_request import ProbeReq
from Mngmt_frames.Probe_response import Proberesp
from Mngmt_frames.ReassoReq import ReassoReq
from Mngmt_frames.ReassoResp import ReassoResp
from Connection_monitors.DeauthMonitor import DeauthMon
from Connection_monitors.AlivenessCheck import AllvCheck
from Msgs_colors import bcolors
from Ctrl_frames.ControlFrames import ControlFrames
from Data_frames.DataFrames import DataFrames
from fuzzer_init import *
from time import sleep
import threading
import settings
import sys
import os
import ascii_art
from Mngmt_frames.FuzzMngmntFrames import fuzzMngmtFrames
from Ctrl_frames.fuzzControlFrames import fuzzControlFrames
from Data_frames.fuzzDataFrames import fuzzDataFrames

global fuzzer

print(ascii_art.logo)
print(
    '- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n\n')
print(
    '\t\tThis tool is capable of fuzzing either any management, control or data frame of the 802.11\n\t\tprotocol or the SAE exchange. For the management, control or data frames, you can choose\n\t\teither the "standard" mode where all of the frames transmitted have valid size values or\n\t\tthe "random" mode where the size value is random. The SAE fuzzing operation requires an AP\n\t\tthat supports WPA3. Management, control or data frame fuzzing can be executed against any AP\n\t\t(WPA2 or WPA3). Finally, a DoS attack vector is implemented, which exploits the findings of\n\t\tthe management, control or data frames fuzzing.\n')
print(
    '- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n\n')

print('1) Fuzz Management Frames')
print('2) Fuzz SAE exchange')
print('3) Fuzz Control Frames')
print('4) Fuzz Data Frames ' + bcolors.WARNING + '(BETA)' + bcolors.ENDC)
print('5) DoS attack module\n\n')
try:
    choice = int(input('Enter a choice: '))
except:
    print('\n' + bcolors.FAIL + 'Only integer inputs accepted' + bcolors.ENDC)
    os._exit(0)

if (choice == 1 or choice == 3 or choice == 4):
    subprocess.call(['clear'], shell=True)
    print(ascii_art.mngmt_frames)
    print('Please choose fuzzer tool:')
    print('1) Blab')
    print('2) gramfuzz')
    fuzzer = int(input('Enter a choice for fuzzer: '))
    if fuzzer != 1 and fuzzer != 2:
        print(bcolors.FAIL + '\nNo such fuzzer :(' + bcolors.ENDC)
        os._exit(0)

    print('Type "standard" for the standard mode')
    print('Type "random" for the random mode\n\n')
    mode = input('Enter a choice: ').lower()
    if mode == 'standard' or mode == 'random':
        Aliveness = AllvCheck(targeted_STA, 'fuzzing')
        Aliveness.start()
        while not settings.retrieving_IP:
            if settings.IP_not_alive:
                os._exit(0)
        sleep(10)
        subprocess.call(['clear'], shell=True)
    else:
        print(bcolors.FAIL + '\nNo such mode :(' + bcolors.ENDC)
        os._exit(0)

if choice == 1:
    subprocess.call(['clear'], shell=True)
    fuzzMngmtFrames(mode)

elif choice == 2:
    subprocess.call(['clear'], shell=True)
    subprocess.call(['sudo python3 dos-sae.py'], shell=True)
elif choice == 3:
    subprocess.call(['clear'], shell=True)
    print(ascii_art.control_frames)
    fuzzControlFrames(mode)
elif choice == 4:
    subprocess.call(['clear'], shell=True)
    fuzzDataFrames(mode)
elif choice == 5:
    subprocess.call(['clear'], shell=True)
    subprocess.call(['sudo python3 mage.py'], shell=True)
else:
    print(bcolors.FAIL + '\nNo such choice :(' + bcolors.ENDC)
