import subprocess
import sys

from Msgs_colors import bcolors
from time import sleep
import os
import ascii_art
from Mngmt_frames.FuzzMngmntFrames import fuzzMngmtFrames
from Ctrl_frames.fuzzControlFrames import fuzzControlFrames
from Data_frames.fuzzDataFrames import fuzzDataFrames
import argparse
from src import utils

parser = argparse.ArgumentParser(description="WPAxFuzz tool options", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument("-u", "--url", help="HTTP Server url. Cannot used along with -a.")
parser.add_argument("-p", "--port", type=int, help="Port. Cannot used along with -a.")
parser.add_argument("-t", "--type", type=str, help="Specify the frame type to fuzz. Types are: 'management', 'control' and 'data'.")
parser.add_argument("-s", "--subtype", type=int, help="Specify the frame Subtype.")
parser.add_argument("-d", "--dos", action="store_true", help="DoS attack module.")
parser.add_argument("-g", "--generator", type=str, help="Specify generator. Allowed generators: 'blab' and 'gramfuzz'.")
parser.add_argument("-m", "--mode", type=str, help="Specify mode option. Allowed options: 'standard' or 'random'.")
parser.add_argument("-a", "--aliveness", type=str, help="Specify if Aliveness will be set or not. Allowed options: 'yes' or 'no'. Cannot used along with -u and -p")
args = parser.parse_args()

os.system('cat src/logo.txt')

if len(sys.argv) == 1:
    print("\n")
    parser.print_help()
    sys.exit(1)

utils.argumentsValidation(args.url, args.port, args.aliveness, args.dos, args.type, args.subtype, args.generator, args.mode, sys.argv)

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