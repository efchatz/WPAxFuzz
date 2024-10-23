import subprocess
import os
import ascii_art
from Mngmt_frames import AssoReq
from Mngmt_frames import AssoResp
from Mngmt_frames import Authentication
from Mngmt_frames import Beacon
from Mngmt_frames import ReassoReq
from Mngmt_frames import ReassoResp
from Connection_monitors.DeauthMonitor import DeauthMon
from Mngmt_frames.Action import Action
from Mngmt_frames.Probe_request import ProbeReq
from Mngmt_frames.Probe_response import Proberesp
from Msgs_colors import bcolors
from fuzzer_init import *
from time import sleep

def fuzzMngmtFrames(generator, mode):
    subprocess.call(['clear'], shell=True)
    print(ascii_art.mngmt_frames)
    print('Which Management frames would you like to fuzz?')
    print('1) Beacon frames')
    print('2) Probe request frames')
    print('3) Probe response frames')
    print('4) Association request frames')
    print('5) Association response frames')
    print('6) Reassociation request frames')
    print('7) Reassociation response frames')
    print('8) Authentication frames')
    print('9) Action frames\n\n')
    try:
        management_frame = int(input('Select a management frame to fuzz (1-9): '))
    except:
        print('\n' + bcolors.FAIL + 'Only integer inputs accepted' + bcolors.ENDC)
        os._exit(0)
    Deauth_monitor = DeauthMon(targeted_AP, targeted_STA, att_interface)
    Deauth_monitor.start()
    if management_frame == 1:
        if mode == 'random':
            subprocess.call(['clear'], shell=True)
            print(ascii_art.beacon)
            direction = impersonation_option()
        else:
            direction = 1
        fuzz_beacons = Beacon.Beacon(generator, mode, "beacon", targeted_STA, targeted_AP, att_interface, real_ap_ssid, direction)
        subprocess.call(['clear'], shell=True)
        print(ascii_art.beacon)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        sleep(5)
        fuzz_beacons.fuzz_beacon()
    elif management_frame == 2:
        fuzz_probe_reqs = ProbeReq(generator, mode, "probe request", targeted_AP, targeted_STA, att_interface, real_ap_ssid)
        subprocess.call(['clear'], shell=True)
        print(ascii_art.probe_req)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        sleep(5)
        fuzz_probe_reqs.fuzz_probe_req()
    elif management_frame == 3:
        if mode == 'random':
            subprocess.call(['clear'], shell=True)
            print(ascii_art.probe_resp)
            direction = impersonation_option()
        else:
            direction = 1
        fuzz_probe_resp = Proberesp(generator, mode, "probe response", targeted_STA, targeted_AP, att_interface, real_ap_ssid, direction)
        subprocess.call(['clear'], shell=True)
        print(ascii_art.probe_resp)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        sleep(5)
        fuzz_probe_resp.fuzz_probe_resp()
    elif management_frame == 4:
        fuzz_asso_reqs = AssoReq.AssoReq(generator, mode, "association request", targeted_AP, targeted_STA, att_interface, real_ap_ssid)
        subprocess.call(['clear'], shell=True)
        print(ascii_art.asso_req)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        sleep(5)
        fuzz_asso_reqs.fuzz_asso_req()
    elif management_frame == 5:
        if mode == 'random':
            subprocess.call(['clear'], shell=True)
            print(ascii_art.asso_resp)
            direction = impersonation_option()
        else:
            direction = 1
        fuzz_asso_resp = AssoResp.AssoResp(generator, mode, "association response", targeted_STA, targeted_AP, att_interface, direction)
        subprocess.call(['clear'], shell=True)
        print(ascii_art.asso_resp)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        sleep(5)
        fuzz_asso_resp.fuzz_asso_resp()
    elif management_frame == 6:
        fuzz_reasso_reqs = ReassoReq.ReassoReq(generator, mode, "reassociation request", targeted_AP, targeted_STA, att_interface, real_ap_ssid)
        subprocess.call(['clear'], shell=True)
        print(ascii_art.reasso_req)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        sleep(5)
        fuzz_reasso_reqs.fuzz_reasso_req()
    elif management_frame == 7:
        if mode == 'random':
            subprocess.call(['clear'], shell=True)
            print(ascii_art.reasso_resp)
            direction = impersonation_option()
        else:
            direction = 1
        fuzz_asso_resp = ReassoResp.ReassoResp(generator, mode, "reassociation response", targeted_STA, targeted_AP, att_interface, direction)
        subprocess.call(['clear'], shell=True)
        print(ascii_art.reasso_resp)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        sleep(5)
        fuzz_asso_resp.fuzz_reasso_resp()
    elif management_frame == 8:
        fuzz_auth = Authentication.Authentication(generator, mode, "authentication", targeted_AP, targeted_STA, att_interface)
        subprocess.call(['clear'], shell=True)
        print(ascii_art.auth)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        sleep(5)
        fuzz_auth.fuzz_auth()
    elif management_frame == 9:
        fuzz_action = Action(generator, mode, "action", targeted_STA, targeted_AP, att_interface,)
        subprocess.call(['clear'], shell=True)
        print(ascii_art.wifi)
        print("Fasten your seatbelts and grab a coffee. Fuzzing is about to begin!")
        sleep(5)
        fuzz_action.fuzz_action()

def impersonation_option():
    print(ascii_art.wifi)
    print("1) Target the STA and impersonate the AP")
    print("2) Target the AP and impersonate the STA\n\n")
    try:
        direction = int(input('Please provide your choice: '))
    except:
        print('\n' + bcolors.FAIL + 'Only integer inputs accepted' + bcolors.ENDC)
        os._exit(0)
    if direction in {1, 2}:
        return direction
    else:
        print(bcolors.FAIL + '\nNo such choice exist :(' + bcolors.ENDC)
        os._exit(0)