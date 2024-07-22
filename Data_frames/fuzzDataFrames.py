import subprocess
import os
import ascii_art
from Msgs_colors import bcolors
from Data_frames.DataFrames import DataFrames
from fuzzer_init import *
from time import sleep

def fuzzDataFrames(generator, mode):
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
        data_frame = int(input('Select a frame to fuzz: '))
    except:
        print('\n' + bcolors.FAIL + 'Only integer inputs accepted' + bcolors.ENDC)
        os._exit(0)
    if direction == 1:
        fuzz_data = DataFrames(targeted_STA, targeted_AP, att_interface, generator, mode, data_frame, True)
    else:
        fuzz_data = DataFrames(targeted_AP, targeted_STA, att_interface, generator, mode, data_frame, False)
    subprocess.call(['clear'], shell=True)
    print(ascii_art.data_frames)
    print(ascii_art.wifi)
    print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
    sleep(5)
    print(fuzz_data.fuzz_data_frames())