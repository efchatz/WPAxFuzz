import subprocess
import os
import ascii_art
from Connection_monitors.AlivenessCheck import AllvCheck
from Msgs_colors import bcolors
from Data_frames.DataFrames import DataFrames
from fuzzer_init import *
from time import sleep
import settings

def fuzzDataFrames(mode):
    print(ascii_art.data_frames)
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
    subprocess.call(['clear'], shell=True)
    print(ascii_art.data_frames)
    print("1) Target the STA and impersonate the AP")
    print("2) Target the AP and impersonate the STA\n\n")
    try:
        direction = int(input('Select a frame to fuzz: '))
    except:
        print('\n' + bcolors.FAIL + 'Only integer inputs accepted' + bcolors.ENDC)
        os._exit(0)
    if direction in {1, 2}:
        pass
    else:
        print(bcolors.FAIL + '\nNo such mode :(' + bcolors.ENDC)
        os._exit(0)
    subprocess.call(['clear'], shell=True)
    print(ascii_art.data_frames)
    print('Which frames would you like to fuzz?')
    print('1) Data')
    print('2) Data + CF-ACK')
    print('3) Data + CF-Poll')
    print('4) Data + CF-Ack + CF-Poll')
    print('5) Null Data')
    print('6) CF-ACK (no data)')
    print('7) CF-Poll (no data)')
    print('8) CF-ACK + CF-Poll (no data)')
    print('9) QoS Data')
    print('10) QoS Data + CF-ACK')
    print('11) QoS Data + CF-Poll')
    print('12) QoS Data + CF-ACK + CF-Poll')
    print('13) QoS Null Data')
    print('14) Reserved Data Frame')
    print('15) QoS Data + CF-Poll (no data)')
    print('16) QoS CF-ACK + CF-Poll (no data)\n\n')
    try:
        choice2 = int(input('Select a frame to fuzz: '))
    except:
        print('\n' + bcolors.FAIL + 'Only integer inputs accepted' + bcolors.ENDC)
        os._exit(0)
    if direction == 1:
        fuzz_data = DataFrames(targeted_STA, targeted_AP, att_interface, mode, choice2, True)
    else:
        fuzz_data = DataFrames(targeted_AP, targeted_STA, att_interface, mode, choice2, False)
    subprocess.call(['clear'], shell=True)
    print(ascii_art.data_frames)
    print(ascii_art.wifi)
    print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
    sleep(5)
    print(fuzz_data.fuzz_data_frames())