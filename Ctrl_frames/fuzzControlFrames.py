import subprocess
import os
import ascii_art
from Msgs_colors import bcolors
from Ctrl_frames.ControlFrames import ControlFrames
from fuzzer_init import *
from time import sleep

def fuzzControlFrames(generator, mode):
    subprocess.call(['clear'], shell=True)
    print(ascii_art.control_frames)
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
    print(ascii_art.control_frames)
    print('Which frames would you like to fuzz?')
    print('1) Trigger')
    print('2) TACK')
    print('3) Beamforming Report Poll')
    print('4) VHT/HE NDP Announcement')
    print('5) Control Frame Extension')
    print('6) Control wrapper')
    print('7) Block Ack Request (BAR)')
    print('8) Block ACK')
    print('9) PS-Poll (Power Save-Poll)')
    print('10) RTS–Request to Send')
    print('11) CTS-Clear to Send')
    print('10) ACK')
    print('11) CF-End (Contention Free-End)')
    print('12) CF-End & CF-ACK\n\n')
    try:
        control_frame = int(input('Select a frame to fuzz: '))
    except:
        print('\n' + bcolors.FAIL + 'Only integer inputs accepted' + bcolors.ENDC)
        os._exit(0)
    if control_frame == 5:
        subprocess.call(['clear'], shell=True)
        print(ascii_art.control_frames)
        print('Which frames would you like to fuzz?')
        print('1) Poll')
        print('2) Service period request')
        print('3) Grant')
        print('4) DMG CTS')
        print('5) DMG DTS')
        print('6) Grant Ack')
        print('7) Sector sweep (SSW)')
        print('8) Sector sweep feedback (SSW-Feedback)')
        print('9) Sector sweep Ack (SSW-Ack)\n\n')
        try:
            ctrl_frm_ext = int(input('Select a frame to fuzz: '))
        except:
            print('\n' + bcolors.FAIL + 'Only integer inputs accepted' + bcolors.ENDC)
            os._exit(0)
        if direction == 1:
            fuzz_ctrl = ControlFrames(targeted_STA, targeted_AP, att_interface, generator, mode, control_frame, ctrl_frm_ext + 1)
        else:
            fuzz_ctrl = ControlFrames(targeted_AP, targeted_STA, att_interface, generator, mode, control_frame, ctrl_frm_ext + 1)
    else:
        if direction == 1:
            fuzz_ctrl = ControlFrames(targeted_STA, targeted_AP, att_interface, generator, mode, control_frame, 0)
        else:
            fuzz_ctrl = ControlFrames(targeted_AP, targeted_STA, att_interface, generator, mode, control_frame, 0)
    subprocess.call(['clear'], shell=True)
    print(ascii_art.control_frames)
    print(ascii_art.wifi)
    print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
    sleep(5)
    print(fuzz_ctrl.fuzz_ctrl_frames())