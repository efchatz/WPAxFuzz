import subprocess
import os
import pandas as pd
from Frame_types.Construct_frame_fields import bcolors
from time import sleep
import sys


config = open('src/config.conf', 'r')
Lines = config.readlines()
for line in Lines:
    if 'AP_MAC_ADDRESS' in line:
        info = line.partition(' ')
        targeted_AP = info[len(info) - 1].strip().lower()
    elif 'ATTACKING_INTERFACE' in line:
        info = line.partition(' ')
        att_interface = info[len(info) - 1].strip()
    elif 'TARGETED_STA_MAC_ADDRESS' in line:
        info = line.partition(' ')
        targeted_STA = info[len(info) - 1].strip().lower()
    elif 'AP_SSID' in line:
        info = line.partition(' ')
        real_ap_ssid = info[len(info) - 1].strip()

def is_NIC_alive():
    intrf_check = subprocess.check_output(['sudo iw ' + att_interface + " info" ' > /dev/null && echo found || echo notfound'], shell=True)
    if intrf_check.decode("utf-8").strip() == 'found':
        pass
    else:
        print("\n\n" + bcolors.FAIL + 'Attacking interface does not exist.' + bcolors.ENDC)
        sys.exit()

def initiate_NIC():
    is_NIC_alive()
    print("\n\n" + bcolors.OKGREEN + "----Initiating injecting NIC----" + bcolors.ENDC)
    subprocess.run(['sudo airmon-ng > /dev/null'], shell=True)
    subprocess.run(['sudo airmon-ng check kill > /dev/null'], shell=True)
    subprocess.run(['sudo airmon-ng start ' + att_interface + ' > /dev/null'], shell=True)
    try:
        band = int(input('\nWhich frequency band does your AP transmits on\n1) 2.4GHz\n2) 5GHz\nMake your choice: '))
    except:
        print('\n' + bcolors.FAIL + 'Only integer inputs accepted' + bcolors.ENDC)
        sys.exit()
    if band == 1:
        subprocess.run(['sudo timeout 12 airodump-ng -w output.txt --output-format csv ' + att_interface + ' --essid ' + real_ap_ssid + ' > /dev/null'], shell=True)
    elif band == 2:
        subprocess.run(['sudo timeout 25 airodump-ng --band a -w output.txt --output-format csv ' + att_interface + ' --essid ' + real_ap_ssid + ' > /dev/null'], shell=True)
    else:
        print('\n' + bcolors.FAIL + 'No such band'+ bcolors.ENDC)
        sys.exit()
    try:
        df = pd.read_csv('output.txt-01.csv', usecols=[3], low_memory=False)
        AP_channel = df.iat[0, 0]
        int(AP_channel)
    except:
        print(bcolors.FAIL + "Exiting Fuzzer. Something is wrong with your NIC or the tarrgeted AP!" + bcolors.ENDC)
        os.remove("output.txt-01.csv")
        sys.exit()
    subprocess.run(['sudo iw ' + att_interface + ' set channel' + AP_channel + ' HT20'], shell=True)
    print(bcolors.OKGREEN + "----Your NIC is on monitor mode and it transmits on channel" + AP_channel + "----" + bcolors.ENDC)
    os.remove("output.txt-01.csv")

def find_APs_sec():
    is_NIC_alive()
    print("\n\n" + bcolors.OKGREEN + "----Finding targeted AP security standard----" + bcolors.ENDC)
    subprocess.run(['sudo timeout 15 airodump-ng -w output.txt --output-format csv ' + att_interface + ' --essid ' + real_ap_ssid + ' > /dev/null'], shell=True)
    df = pd.read_csv('output.txt-01.csv', usecols=[5], low_memory=False)
    os.remove("output.txt-01.csv")
    return df.iat[0, 0][1:5]
