import ipaddress
import json
import os
import subprocess

from Msgs_colors import bcolors

def argumentsValidation(ip, port, aliveness, dos, type, subtype, generator, mode, arguments):
    frames = json.load(open('src/frames.json','r'))
    lowercase_frames = {key.lower(): value for key, value in frames.items()}

    if dos and len(arguments) > 2:
        print(bcolors.FAIL + "\n\t\tCannot provide other arguments when -d (--dos) argument is set." + bcolors.ENDC)
        os._exit(0)

    frameValidation(lowercase_frames, type, subtype)
    monitoringValidation(ip, port, aliveness, dos, arguments)
    generatorValidator(generator)
    modeValidator(mode)
    alivnessValidator(aliveness)

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

    if type not in frames.keys():
        print(bcolors.FAIL + f"\n\t\tType is not valid!\n\t\tValid Types:'management', 'control', 'data'"+ bcolors.ENDC)
        os._exit(0)

    if subtype not in frames[type].values():
        print(bcolors.FAIL + f"\n\t\tThis Subtype is not included in {type}'s subtypes!"+ bcolors.ENDC)
        os._exit(0)

def monitoringValidation(ip, port, aliveness, dos, arguments):
    if (ip and not port) or (not ip and port) or (not ip and not port and not aliveness):
        print(bcolors.FAIL + "\n\t\tMonitoring method is not set.\n\t\tProvide a URL (-u) and a Port (-p) for HTTP Server or set Aliveness (-a) as a monitoring method.\n\t\tIf you don't want to set a Monitoring method, set Aliveness to 'no' (-a no)." + bcolors.ENDC)
        os._exit(0)
    elif not ip and not port:
        return True
    elif ip and port and aliveness:
        print(bcolors.FAIL + "\n\t\tHTTP server is set as a monitoring method. Cannot set aliveness!" + bcolors.ENDC)
        os._exit(0)
    else:
        ipValidation(ip)
        portValidation(port)

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

def alivnessValidator(aliveness_option):
    options = ['yes', 'no']
    if aliveness_option not in options:
        print(bcolors.FAIL + f"\n\t\tThis is not a valid aliveness option!\n\t\tValid aliveness options are: 'yes' and 'no'." + bcolors.ENDC)
        os._exit(0)

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