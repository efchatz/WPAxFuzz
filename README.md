# WPAxFuzz

## A full-featured open-source Wi-Fi fuzzer    
This tool is capable of fuzzing either any management frame of the 802.11 protocol or the SAE exchange. For the management frames, you can choose either the "standard" mode where all of the frames transmitted have valid size values or the "random" mode where the size value is random. The SAE fuzzing operation requires an AP that supports WPA3. Management frame fuzzing can be executed against any AP (WPA2 or WPA3).

## Fuzz Management Frames

### Prequisites
1)SCAPY: https://scapy.readthedocs.io/en/latest/  
2)BLAB: https://gitlab.com/akihe/blab  
3)PANDAS: https://pandas.pydata.org/  

### Requirements and dependencies
1) Before initializing the tool, the user has to probe the local network to discover any potential targets, i.e., STAs and APs.
```
    nmap -sP {ip_prefix}.*
```
2) In case the fuzz testing is executed on a Virtual Machine (VM), and the targeted STA happens to also run on the host machine, it may lead to mistaken deductions. It is recommended to place the STA and the fuzzing operation to different physical machines.
3) If the targeted STA is an MS Windows OS machine, it may be necessary to modify the firewall to allow ``pinging'' within the local network. It is necessecary so that the monitoring mode for the aliveness of the STA operates correctly.
5) Considering the Blab tool for the seed generation, due to OS inconsistencies you have to place the binary file of Blab to the main directory of the fuzzer project. In this way, the fuzzer is compatible regardless the host OS.
```
    git clone https://haltp.org/git/blab.git
    cd blab/
    make
    cd {binary directory, where Blab is saved}                    ex. cd /bin/blab/bin
    cp blab {fuzzer directory}                                    ex. cp blab /home/kali/Desktop/WPAxFuzz
```

### Description
STEP1: Inform the config file with the targeted AP and STA MAC addresses, the SSID of the AP and the interface name, which will be injecting the frames.  
STEP2: Run the fuzzer via the command 
```
    sudo python3 fuzz.py
```
STEP3: Input the frequency band that the targeted AP transmites on. The tool is responsible to automatically detect and set the right channel for the injecting interface, namely the same with the AP.    
STEP4: After the injecting interface initialization that is being held automatically, pick one of the following modes:  
```
    Standard: All the frame fields, including the ones being produced with ``Blab'',  
    carry a value length that abides by the 802.11 standard. This way, the frame will not risk  
    to be characterized as malformed and dropped.  
    
    Random: The fields produced via the seed generator have a random value length,  
    which can be either lesser or greater than that defined by the 802.11 standard.  
```
STEP5: The tool will check if the STA is alive, meaning connected to the targeted AP and then it will ask for the user to pick one of the following frames to fuzz with:
```
    1) Beacon frames
    2) Probe request frames
    3) Probe response frames
    4) Association request frames
    5) Association response frames
    6) Reassociation request frames
    7) Reassociation response frames
    8) Authentication frames
```
STEP6: From this point on the only interaction with the user is when a connection interruption happens or a deauthentication/disassociation frame is detected. In this case, the user is being asked to reconnect and resume the fuzzing process.
