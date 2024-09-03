import ipaddress
import os

import settings
from Connection_monitors.AlivenessCheck import AllvCheck
from Connection_monitors.HttpServerCheck import HttpCheck
from Msgs_colors import bcolors
from fuzzer_init import targeted_STA


def validate_arguments(ip, port):
    if ((ip and not port) or (not ip and port)):
        print(bcolors.FAIL + "Wrong arguments provided!" + bcolors.ENDC)
        os._exit(0)
    else:
        validate_ip(ip)
        validate_port(port)

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        print(bcolors.FAIL + f"The IP {ip} is not valid!" + bcolors.ENDC)
        os._exit(0)

def validate_port(port):
    if 0 < port <= 65535:
        return True
    print(bcolors.FAIL + "Port argument is not valid!" + bcolors.ENDC)
    os._exit(0)

def generator_tool_option():
    print('Please choose generator tool:')
    print('1) Blab')
    print('2) gramfuzz')
    generator = int(input('Enter a choice for generator (1 for Blab or 2 for gramfuzz): '))
    if generator != 1 and generator != 2:
        print(bcolors.FAIL + '\nNo such generator :(' + bcolors.ENDC)
        os._exit(0)
    return generator

def mode_option():
    print('\nType "standard" for the standard mode')
    print('Type "random" for the random mode\n\n')
    mode = input('Enter a choice: ').lower()
    if mode !='standard' and mode != 'random':
        print(bcolors.FAIL + '\nNo such mode :(' + bcolors.ENDC)
        os._exit(0)
    return mode

def monitoring_method_option(url,port):
    if url and port:
        print(bcolors.OKBLUE + "\nYou provided HTTP server IP, so HTTP server check is used as monitoring method." + bcolors.ENDC)
        http_check = HttpCheck(url, port, 'fuzzing')
        http_check.start()
        while not settings.retrieving_IP:
            if settings.IP_not_alive:
                os._exit(0)
    else:
        print('\nDo you want to start Aliveness? Type "yes" or "no":')
        aliveness = input().lower
        if aliveness == 'yes':
            Aliveness = AllvCheck(targeted_STA, 'fuzzing')
            Aliveness.start()
            while not settings.retrieving_IP:
                if settings.IP_not_alive:
                    os._exit(0)