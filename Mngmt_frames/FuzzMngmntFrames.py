import subprocess
import os
from WPAxFuzz import ascii_art
from WPAxFuzz.Mngmt_frames import AssoReq
from WPAxFuzz.Mngmt_frames import AssoResp
from WPAxFuzz.Mngmt_frames import Authentication
from WPAxFuzz.Mngmt_frames import Beacon
from WPAxFuzz.Mngmt_frames import ReassoReq
from WPAxFuzz.Mngmt_frames import ReassoResp
from WPAxFuzz.Connection_monitors.DeauthMonitor import DeauthMon
from WPAxFuzz.Mngmt_frames.Probe_request import ProbeReq
from WPAxFuzz.Mngmt_frames.Probe_response import Proberesp
from WPAxFuzz.Msgs_colors import bcolors
from WPAxFuzz.fuzzer_init import *
from time import sleep

def fuzzMngmtFrames(fuzzer, mode):
    subprocess.call(['clear'], shell=True)
    print(ascii_art.mngmt_frames)
    print('Which frames would you like to fuzz?')
    print('1) Beacon frames')
    print('2) Probe request frames')
    print('3) Probe response frames')
    print('4) Association request frames')
    print('5) Association response frames')
    print('6) Reassociation request frames')
    print('7) Reassociation response frames')
    print('8) Authentication frames\n\n')
    try:
        choice2 = int(input('Select a frame to fuzz: '))
    except:
        print('\n' + bcolors.FAIL + 'Only integer inputs accepted' + bcolors.ENDC)
        os._exit(0)
    Deauth_monitor = DeauthMon(targeted_AP, targeted_STA, att_interface)
    Deauth_monitor.start()
    if choice2 == 1:
        if mode == 'random':
            subprocess.call(['clear'], shell=True)
            print(ascii_art.beacon)
            print(ascii_art.wifi)
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
        else:
            direction = 1
        fuzz_beacons = Beacon(fuzzer, mode, "beacon", targeted_STA, targeted_AP, att_interface, real_ap_ssid, direction)
        subprocess.call(['clear'], shell=True)
        print(ascii_art.beacon)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        sleep(5)
        fuzz_beacons.fuzz_beacon()
    elif choice2 == 2:
        fuzz_probe_reqs = ProbeReq(fuzzer, mode, "probe request", targeted_AP, targeted_STA, att_interface, real_ap_ssid)
        subprocess.call(['clear'], shell=True)
        print(ascii_art.probe_req)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        sleep(5)
        fuzz_probe_reqs.fuzz_probe_req()
    elif choice2 == 3:
        if mode == 'random':
            subprocess.call(['clear'], shell=True)
            print(ascii_art.probe_resp)
            print(ascii_art.wifi)
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
        else:
            direction = 1
        fuzz_probe_resp = Proberesp(fuzzer, mode, "probe response", targeted_STA, targeted_AP, att_interface, real_ap_ssid, direction)
        subprocess.call(['clear'], shell=True)
        print(ascii_art.probe_resp)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        sleep(5)
        fuzz_probe_resp.fuzz_probe_resp()
    elif choice2 == 4:
        fuzz_asso_reqs = AssoReq(fuzzer, mode, "association request", targeted_AP, targeted_STA, att_interface, real_ap_ssid)
        subprocess.call(['clear'], shell=True)
        print(ascii_art.asso_req)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        sleep(5)
        fuzz_asso_reqs.fuzz_asso_req()
    elif choice2 == 5:
        if mode == 'random':
            subprocess.call(['clear'], shell=True)
            print(ascii_art.asso_resp)
            print(ascii_art.wifi)
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
        else:
            direction = 1
        fuzz_asso_resp = AssoResp(fuzzer, mode, "association response", targeted_STA, targeted_AP, att_interface, direction)
        subprocess.call(['clear'], shell=True)
        print(ascii_art.asso_resp)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        sleep(5)
        fuzz_asso_resp.fuzz_asso_resp()
    elif choice2 == 6:
        fuzz_reasso_reqs = ReassoReq(fuzzer, mode, "reassociation request", targeted_AP, targeted_STA, att_interface, real_ap_ssid)
        subprocess.call(['clear'], shell=True)
        print(ascii_art.reasso_req)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        sleep(5)
        fuzz_reasso_reqs.fuzz_reasso_req()
    elif choice2 == 7:
        if mode == 'random':
            subprocess.call(['clear'], shell=True)
            print(ascii_art.reasso_resp)
            print(ascii_art.wifi)
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
        else:
            direction = 1
        fuzz_asso_resp = ReassoResp(fuzzer, mode, "reassociation response", targeted_STA, targeted_AP, att_interface, direction)
        subprocess.call(['clear'], shell=True)
        print(ascii_art.reasso_resp)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        sleep(5)
        fuzz_asso_resp.fuzz_reasso_resp()
    elif choice2 == 8:
        fuzz_auth = Authentication(fuzzer, mode, "authentication", targeted_AP, targeted_STA, att_interface)
        subprocess.call(['clear'], shell=True)
        print(ascii_art.auth)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        sleep(5)
        fuzz_auth.fuzz_auth()