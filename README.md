# WPAxFuzz

## A full-featured open-source Wi-Fi fuzzer 
This tool is capable of fuzzing either any management, control or data frame of the 802.11 protocol or the SAE exchange. For the management, control or data frames, you can choose either the "standard" mode where all of the frames transmitted have valid size values or the "random" mode where the size value is random. The SAE fuzzing operation requires an AP that supports WPA3. Management, control or data frame fuzzing can be executed against any AP (WPA2 or WPA3). Finally, a DoS attack vector is implemented, which exploits the findings of the management, control or data frames fuzzing. Overall, WPAxFuzz offers  the below options:
```
    1) Fuzz Management Frames
    2) Fuzz SAE exchange
    3) Fuzz Control Frames
    4) Fuzz Data Frames (BETA)
    5) DoS attack module
```
You can execute the tool using the below command:
```
    sudo python3 fuzz.py
```

## Fuzz Management, Control and Data Frames

### Perquisites
1) SCAPY: https://scapy.readthedocs.io/en/latest/  
2) BLAB: https://gitlab.com/akihe/blab   
4) NMAP: https://nmap.org/download.html

### Requirements and dependencies
1) Before initializing the tool, the user has to probe the local network to discover any potential targets, i.e., STAs and APs.
```
    nmap -sP {ip_prefix}.*
```
2) In case the fuzz testing is executed on a Virtual Machine (VM), and the targeted STA happens to also run on the host machine, it may lead to false deductions. It is recommended to place the STA and the fuzzing operation to different physical machines.
3) If the targeted STA is an MS Windows OS machine, it may be necessary to modify the firewall to allow ``pinging'' within the local network. This enables the monitoring mode to check the aliveness of the associated STA..
5) Regarding the Blab tool (seed generation), due to OS inconsistencies you have to place the binary file of Blab to the main directory of the fuzzer project. In this way, the fuzzer is compatible regardless the host OS.
```
    git clone https://haltp.org/git/blab.git
    cd blab/
    make
    cd {binary directory, where Blab is saved}                    ex. cd /bin/blab/bin
    cp blab {fuzzer directory}                                    ex. cp blab /home/kali/Desktop/WPAxFuzz
```

### Description
STEP1: Update the config file with the (i) targeted AP and associated STA MAC addresses, (ii) SSID of the AP,  and (iii) the wireless interface name.  
STEP2: Set the WNIC to monitor mode:  
```
    sudo airmon-ng
    sudo airmon-ng check
    sudo airmon-ng check kill
    sudo airmon-ng start {NAME_OF_ATT_INTER}
```
STEP3: Set the channel of your WNIC to be the same as the one the targeted AP transmits on:
```
    sudo airodump-ng {NAME_OF_ATT_INTER} \\to find the channel that targeted AP transmits on
    sudo iw {NAME_OF_ATT_INTER} set channel {AP_channel} HT20 \\to set channel to your WNIC
```
STEP4: Choose  option (1), (3) or (4) namely:
```
    1) Fuzz management frames
    3) Fuzz Control Frames
    4) Fuzz Data Frames (BETA)
```
STEP5: Choose one of the following modes:  
```
    Standard: All the frame fields, including the ones being produced with ``Blab'',  
    carry a value length that abides by the 802.11 standard. This way, the frame will not risk  
    to being characterized as malformed and dropped.  
    
    Random: The fields produced via the seed generator have a random value length,  
    which can be either lesser or greater than that defined by the 802.11 standard.  
```

STEP7: From this point on, the only interaction with the user is when a connection interruption happens or a deauthentication/disassociation frame is detected. In this case, the user is asked to reconnect the STA and resume the fuzzing process.  
STEP8: Exit the fuzzing process with two consecutive Ctrl+c.

## Fuzz SAE-exchange

## DoS802.11 (DoS attack module)
This module launches a DoS attack based on the data (log files) collected from the fuzzing process. It can only be performed against the same AP and STA used during the fuzzing process. Namely, the frames that caused any kind of problematic behavior during the fuzzing are being transmitted in a way decided by the below options.

### Description
STEP1: Pick the option 5), namely:
```
   5) DoS attack module
```
STEP2: Pick the attack module you wish
```
    1) Frames detected at the moment of connectivity disruption, one-by-one
    2) Sequence of frames till the moment a disruption was detected (BETA)
```
STEP3: The first mode of DoS802.11, tests all the frames that the fuzzer detected up to that moment. It is a second hand filtering to separate the true positive from the false positive frames. In case  a frame is positive, i.e., causes a DoS to the associated STA, an exploit is being produced automatically.   
STEP4: DoS802.11 exits when the log files have been considered.  

**The rest to modules are currently in BETA mode. 

## License

MIT License

Copyright (c) 2022 Vyron Kampourakis (Management frames, Control frames, Data frames and DoS tools)<br />
Copyright (c) 2022 Apostolos Dolmes (SAE Exchange tool)<br />
Copyright (c) 2022 Efstratios Chatzoglou
