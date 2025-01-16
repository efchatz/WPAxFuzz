import argparse
import json
import sys

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
parser.add_argument("-sta_mac","--sta_mac", type=str, help="Specify the STA's MAC Address.")
parser.add_argument("-scan", action="store_true", help="Scan the network for potential targets.")
args = parser.parse_args()

if len(sys.argv) == 1:
    print("\n")
    parser.print_help()
    sys.exit(1)

utils.argumentsValidation(args.url, args.port, args.aliveness, args.dos, args.type, args.subtype, args.generator, args.mode, args.sta_mac, args.scan, sys.argv)

config = json.load(open('src/config.json', 'r'))

targeted_AP = config["AP_info"]["AP_MAC_ADDRESS"]
AP_CHANNEL = config["AP_info"]["AP_CHANNEL"]
CHANNEL_DIFFERENT_FREQUENCY = config["AP_info"]["CHANNEL_DIFFERENT_FREQUENCY"]
AP_MAC_DIFFERENT_FREQUENCY = config["AP_info"]["AP_MAC_DIFFERENT_FREQUENCY"]
targeted_STA = config["STA_info"]["TARGETED_STA_MAC_ADDRESS"]
att_interface = config["ATT_interface_info"]["ATTACKING_INTERFACE"]
MONITORING_INTERFACE = config["ATT_interface_info"]["MONITORING_INTERFACE"]
PASSWORD = config["AP_info"]["PASSWORD"]
real_ap_ssid = config["AP_info"]["AP_SSID"]
