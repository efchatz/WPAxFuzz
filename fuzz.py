import subprocess
from Connection_monitors.AlivenessCheck import AllvCheck
from Connection_monitors.HttpServerCheck import HttpCheck
from Msgs_colors import bcolors
from fuzzer_init import *
from time import sleep
import settings
import os
import ascii_art
from Mngmt_frames.FuzzMngmntFrames import fuzzMngmtFrames
from Ctrl_frames.fuzzControlFrames import fuzzControlFrames
from Data_frames.fuzzDataFrames import fuzzDataFrames
import argparse

parser = argparse.ArgumentParser(description="HTTP Server arguments", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument("-u", "--url", action="server_url", help="HTTP Server url")
parser.add_argument("-p", "--port", type=int, action="port", help="Port")
args = vars(parser.parse_args())

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
    print('Please choose generator tool:')
    print('1) Blab')
    print('2) gramfuzz')
    generator = int(input('Enter a choice for generator (1 for Blab or 2 for gramfuzz): '))
    if generator != 1 and generator != 2:
        print(bcolors.FAIL + '\nNo such generator :(' + bcolors.ENDC)
        os._exit(0)

    print('Type "standard" for the standard mode')
    print('Type "random" for the random mode\n\n')
    mode = input('Enter a choice: ').lower()
    if mode !='standard' and mode != 'random':
        print(bcolors.FAIL + '\nNo such mode :(' + bcolors.ENDC)
        os._exit(0)

    print('Please choose monitoring method:')
    print('1) Aliveness')
    print('2) HTTP Server check')
    monitoring_method = int(input('Type "1" for Aliveness or "2" for HTTP server check'))
    match monitoring_method:
        case 1:
            Aliveness = AllvCheck(targeted_STA, 'fuzzing')
            Aliveness.start()
            while not settings.retrieving_IP:
                if settings.IP_not_alive:
                    os._exit(0)
        case 2:
            http_check = HttpCheck(args["url"], args["port"])
            http_check.start()
        case _:
            print(bcolors.FAIL + '\nNo such choice :(' + bcolors.ENDC)
            os._exit(0)
    sleep(10)
    subprocess.call(['clear'], shell=True)
match choice:
    case 1:
        fuzzMngmtFrames(generator, mode)
    case 2:
        subprocess.call(['clear'], shell=True)
        subprocess.call(['sudo python3 dos-sae.py'], shell=True)
    case 3:
        fuzzControlFrames(generator, mode)
    case 4:
        fuzzDataFrames(generator, mode)
    case 5:
        subprocess.call(['clear'], shell=True)
        subprocess.call(['sudo python3 mage.py'], shell=True)
    case _:
        print(bcolors.FAIL + '\nNo such choice :(' + bcolors.ENDC)
        os._exit(0)