import ipaddress
import json
import os
import subprocess
from time import sleep

import settings
from Connection_monitors.AlivenessCheck import AllvCheck
from Connection_monitors.HttpServerCheck import HttpCheck
from Msgs_colors import bcolors
import requests

def argumentsValidation(ip, port, aliveness, dos, type, subtype, generator, mode, sta_mac, arguments):
    frames = json.load(open('src/frames.json','r'))
    lowercase_frames = {key.lower(): value for key, value in frames.items()}

    if dos and len(arguments) > 2:
        print(bcolors.FAIL + "\n\t\tCannot provide other arguments when -d (--dos) argument is set." + bcolors.ENDC)
        os._exit(0)
    elif dos:
        subprocess.call(['sudo python3 mage.py'], shell=True)

    update_config(sta_mac)
    frameValidation(lowercase_frames, type, subtype)
    monitoringValidation(ip, port, aliveness, sta_mac)
    generatorValidator(generator)
    modeValidator(mode)
    alivenessValidator(aliveness)

def ipValidation(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        print(bcolors.FAIL + f"\n\t\tThe IP {ip} is not valid!" + bcolors.ENDC)
        os._exit(0)

def portValidation(port):
    if 0 < port <= 65535:
        return True
    print(bcolors.FAIL + "\n\t\tPort argument is not valid!" + bcolors.ENDC)
    os._exit(0)
    
def frameValidation(frames, type, subtype):

    if not type or not subtype:
        print(bcolors.FAIL + f"\n\t\tPlease provide a valid frame with Type and Subtype."+ bcolors.ENDC)
        os._exit(0)

    if type not in frames.keys():
        print(bcolors.FAIL + f"\n\t\tType is not valid!\n\t\tValid Types:'management', 'control', 'data'"+ bcolors.ENDC)
        os._exit(0)

    if subtype not in frames[type].values():
        print(bcolors.FAIL + f"\n\t\tThis Subtype is not included in {type}'s subtypes!"+ bcolors.ENDC)
        os._exit(0)

def monitoringValidation(ip, port, aliveness, sta_mac):
    if (ip and not port) or (not ip and port) or (not ip and not port and not aliveness):
        print(bcolors.FAIL + "\n\t\tMonitoring method is not set.\n\t\tProvide a URL (-u) and a Port (-p) for HTTP Server or set Aliveness (-a) as a monitoring method.\n\t\tIf you don't want to set a Monitoring method, set Aliveness to 'no' (-a no)." + bcolors.ENDC)
        os._exit(0)
    elif ip and port and aliveness:
        print(bcolors.FAIL + "\n\t\tYou selected both HTTP Server Check and Aliveness as the monitoring method. Please choose only one!" + bcolors.ENDC)
        os._exit(0)
    elif ip and port and not aliveness:
        validIP = ipValidation(ip)
        validPort = portValidation(port)
        if validIP and validPort:
            print(bcolors.OKBLUE + "\nHTTP Server is used as the monitoring method." + bcolors.ENDC)
            check_host_existence(ip)
            http_check = HttpCheck(ip, port, 'fuzzing')
            http_check.start()
            while not settings.retrieving_IP:
                if settings.IP_not_alive:
                    os._exit(0)
    elif not ip and not port and aliveness == 'yes':
        print(bcolors.OKBLUE + "\nAliveness is used as the monitoring method." + bcolors.ENDC)
        Aliveness = AllvCheck(sta_mac, 'fuzzing')
        Aliveness.start()
        while not settings.retrieving_IP:
            if settings.IP_not_alive:
                os._exit(0)

def generatorValidator(generator):
    generators = ['blab', 'gramfuzz']
    if generator not in generators:
        print(bcolors.FAIL + f"\n\t\tThis is not a valid generator!\n\t\tValid generators are: 'blab' and 'gramfuzz'." + bcolors.ENDC)
        os._exit(0)

def modeValidator(mode):
    modes = ['standard', 'random']
    if mode not in modes:
        print(bcolors.FAIL + f"\n\t\tThis is not a valid mode!\n\t\tValid generators are: 'standard' and 'random'." + bcolors.ENDC)
        os._exit(0)

def alivenessValidator(aliveness_option):
    options = ['yes', 'no']
    if aliveness_option not in options:
        print(bcolors.FAIL + f"\n\t\tThis is not a valid aliveness option!\n\t\tValid aliveness options are: 'yes' and 'no'." + bcolors.ENDC)
        os._exit(0)

def check_host_existence(ip):

    def check_host():
        try:
            response = requests.get(ip, timeout=5)
            return response.status_code
        except requests.exceptions.RequestException as e:
            return '1'

    response = check_host()
    if response == 200:
        print("\nThe HTTP Server is Alive!")
        return True

    print(f'\n{bcolors.FAIL}The HTTP Server is down!{bcolors.ENDC}\n')
    while True:
        input(bcolors.WARNING + 'Connect the HTTP Server and press Enter to resume:\n' + bcolors.ENDC)
        if check_host() == 200:
            print(f'{bcolors.OKCYAN}Pausing for 5 seconds and checking again.{bcolors.ENDC}\n')
            sleep(5)

def update_config(mac_address):
    config_path = os.path.join('src', 'config.json')
    with open(config_path, 'r') as file:
        config = json.load(file)

    config['STA_info']['TARGETED_STA_MAC_ADDRESS'] = mac_address

    with open(config_path, 'w') as file:
        json.dump(config, file, indent=4)

def start_sae(targeted_AP, AP_CHANNEL, AP_MAC_DIFFERENT_FREQUENCY, CHANNEL_DIFFERENT_FREQUENCY, targeted_STA, att_interface, MONITORING_INTERFACE, PASSWORD):
    terminal_width = int(subprocess.check_output(['stty', 'size']).split()[1])
    print("\n")
    print('-' * terminal_width)
    print((bcolors.OKGREEN + "INFORMATION RETRIEVED FROM CONFIG FILE" + bcolors.ENDC).center(terminal_width))
    print(('  ' + bcolors.STH + 'AP_MAC:   ' + targeted_AP + bcolors.ENDC).center(terminal_width))
    print(('  ' + bcolors.STH + 'AP_CHANNEL:   ' + AP_CHANNEL + bcolors.ENDC).center(terminal_width))
    print("\n")
    print(
        (bcolors.STH + 'AP_MAC_DIFFERENT_FREQUENCY:   ' + AP_MAC_DIFFERENT_FREQUENCY + bcolors.ENDC).center(terminal_width))
    print(('  ' + bcolors.STH + 'CHANNEL_DIFFERENT_FREQUENCY:   ' + CHANNEL_DIFFERENT_FREQUENCY + bcolors.ENDC).center(
        terminal_width))
    print("\n")
    print(('  ' + bcolors.STH + 'TARGETED_STA_MAC_ADDRESS:   ' + targeted_STA + bcolors.ENDC).center(
        terminal_width))
    print("\n")
    print(('  ' + bcolors.STH + 'ATTACKING INTERFACE:   ' + att_interface + bcolors.ENDC).center(terminal_width))
    print(('  ' + bcolors.STH + 'MONITORING INTERFACE:   ' + MONITORING_INTERFACE + bcolors.ENDC).center(terminal_width))
    print("\n")
    print(('  ' + bcolors.STH + 'PASSWORD:   ' + PASSWORD + bcolors.ENDC).center(terminal_width))
    print('-' * terminal_width)