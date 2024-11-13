import subprocess
from Msgs_colors import bcolors
from time import sleep
import os
import ascii_art
from Mngmt_frames.FuzzMngmntFrames import fuzzMngmtFrames
from Ctrl_frames.fuzzControlFrames import fuzzControlFrames
from Data_frames.fuzzDataFrames import fuzzDataFrames
import argparse
from src import utils

parser = argparse.ArgumentParser(description="HTTP Server arguments", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument("-u", "--url", help="HTTP Server url")
parser.add_argument("-p", "--port", type=int, help="Port")
args = parser.parse_args()

utils.validate_arguments(args.url, args.port)

print(ascii_art.logo)
print(
    '- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n\n')
print(
    '\t\tThis tool is capable of fuzzing either any management, control or data frame of the 802.11\n\t\tprotocol or the SAE exchange. For the management, control or data frames, you can choose\n\t\teither the "standard" mode where all of the frames transmitted have valid size values or\n\t\tthe "random" mode where the size value is random. The SAE fuzzing operation requires an AP\n\t\tthat supports WPA3. Management, control or data frame fuzzing can be executed against any AP\n\t\t(WPA2 or WPA3). Finally, a DoS attack vector is implemented, which exploits the findings of\n\t\tthe management, control or data frames fuzzing.\n')
print(
    '- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n\n')

print('1) Fuzz Management Frames')
print('2) Fuzz Control Frames')
print('3) Fuzz Data Frames ' + bcolors.WARNING + '(BETA)' + bcolors.ENDC)
print('4) DoS attack module\n\n')
try:
    choice = int(input('Enter a choice: '))
except:
    print('\n' + bcolors.FAIL + 'Only integer inputs accepted' + bcolors.ENDC)
    os._exit(0)

if (choice == 1 or choice == 2 or choice == 3):
    subprocess.call(['clear'], shell=True)
    generator = utils.generator_tool_option()
    mode = utils.mode_option()
    utils.monitoring_method_option(args.url, args.port)

    sleep(10)
    subprocess.call(['clear'], shell=True)

match choice:
    case 1:
        fuzzMngmtFrames(generator, mode)
    case 2:
        fuzzControlFrames(generator, mode)
    case 3:
        fuzzDataFrames(generator, mode)
    case 4:
        subprocess.call(['clear'], shell=True)
        subprocess.call(['sudo python3 mage.py'], shell=True)
    case _:
        print(bcolors.FAIL + '\nNo such choice :(' + bcolors.ENDC)
        os._exit(0)