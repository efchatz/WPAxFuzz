import subprocess

from Msgs_colors import bcolors
from time import sleep
import os
import ascii_art
from Mngmt_frames.FuzzMngmntFrames import fuzzMngmtFrames
from Ctrl_frames.fuzzControlFrames import fuzzControlFrames
from Data_frames.fuzzDataFrames import fuzzDataFrames
from fuzzer_init import args

os.system('cat src/logo.txt')

print(ascii_art.logo)
print(
    '- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n\n')
print(
    '\t\tThis tool is capable of fuzzing either any management, control or data frame of the 802.11\n\t\tprotocol or the SAE exchange. For the management, control or data frames, you can choose\n\t\teither the "standard" mode where all of the frames transmitted have valid size values or\n\t\tthe "random" mode where the size value is random. The SAE fuzzing operation requires an AP\n\t\tthat supports WPA3. Management, control or data frame fuzzing can be executed against any AP\n\t\t(WPA2 or WPA3). Finally, a DoS attack vector is implemented, which exploits the findings of\n\t\tthe management, control or data frames fuzzing.\n')
print(
    '- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n\n')

sleep(10)
subprocess.call(['clear'], shell=True)

match args.type:
    case "management":
        fuzzMngmtFrames(args.generator, args.mode, args.subtype)
    case "control":
        fuzzControlFrames(args.generator, args.mode, args.subtype)
    case "data":
        fuzzDataFrames(args.generator, args.mode, args.subtype)
    case _:
        print(bcolors.FAIL + '\nNo such choice :(' + bcolors.ENDC)
        os._exit(0)