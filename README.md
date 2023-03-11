[![Contributors][contributors-shield]][contributors-url]
[![Stargazers][stars-shield]][stars-url]
[![Forks][forks-shield]][forks-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/efchatz/WPAxFuzz">
    <img src="images/logo-no-background.png" alt="Logo" width="430" height="120">
  </a>

  <p align="center">
    <h3 align="center">A full-fledged Wi-Fi Fuzzer</h3>
    <br />
    <a href="https://github.com/efchatz/WPAxFuzz/issues">Report Bug</a>
    ·
    <a href="https://github.com/efchatz/WPAxFuzz/issues">Request Feature</a>
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
    </li>
    <li>
      <a href="#fuzz-management-and-control-and-data-frames">Fuzz Management and Control and Data Frames</a>
      <ul>
        <li><a href="#requirements-and-dependencies">Requirements and Dependencies</a></li>
        <li><a href="#description">Description</a></li>
      </ul>
    </li>
    <li><a href="#fuzz-sae-exchange">Fuzz SAE-exchange</a></li>
    <li><a href="#dos-attack-module">DoS attack module</a>
    <ul>
        <li><a href="#description">Description</a></li>
      </ul>
    </li>
    <li><a href="#vulnerabilities">Vulnerabilities</a></li>
    <li><a href="#related-work">Related Work</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>



## About the project

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



## Fuzz Management and Control and Data Frames


### Requirements and Dependencies

1) Make sure to have the below pre-installed. Probably other versions of Scapy and Python will be applicable too.

    [![Python][Python.py]][Python-url] [![Scapy][Scapy]][Scapy-url] [![Nmap][Nmap]][Nmap-url] [![Blab][Blab]][Blab-url]  

2) Before initializing the tool, the user has to probe the local network to discover any potential targets, i.e., STAs and APs.
```
    nmap -sP {ip_prefix}.*
```
3) In case the fuzz testing is executed on a Virtual Machine (VM), and the targeted STA happens to also run on the host machine, it may lead to false deductions. It is recommended to place the STA and the fuzzing operation to different physical machines.
4) If the targeted STA is an MS Windows OS machine, it may be necessary to modify the firewall to allow ``pinging'' within the local network. This enables the monitoring mode to check the aliveness of the associated STA..
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

This module focuses on the so-called SAE Commit and SAE Confirm Authentication frames which are exchanged during the SAE handshake. According to the 802.11 standard, both these frames carry the Authentication algorithm (3), the Authentication Sequence (1 for Commit and 2 for Confirm), and a Status code, namely, a value between 0 and 65535, with 0 standing for “Successful”. Note that Status code values between 1 and 129 (except 4, 8, 9, 20, 21, 26, 29, 36, 48, 66, 69-71, 90-91, 116, 124, and 127) designate a different failure cause, while the rest are reserved by the protocol. 

In more detail, the current module, selected through WPAxFuzz's CLI, optionally capitalizes on the burst frame sending mode, namely, it sprays multiple frames, i.e., 128, at once towards the target AP. It comprises four different circles: (i) transmit SAE (Authentication) frames to the radio channel the target STA operates, (ii) transmit SAE frames to a different radio channel than that of the target STA(s), and (iii) either of the previous, but with the burst mode enabled. Further, each fuzzing cycle is executed over seven diverse variants based on the stateless approach of WPA3-SAE authentication procedure as follows:
1. An empty SAE auth frame.
2. A valid (well-formed) SAE-Commit frame followed by (1).
3. A valid SAE-Commit frame, followed by a SAE-Confirm frame with the so-called Send-Confirm field set to 0. Recall that the Send-Confirm field carries the counter of the already sent Confirm frames, hence acting as an anti-replay counter.
4. As with (3), but the value of the Send-Confirm field is set to 2. This specific value (2) was chosen, using a value between 2 and 65,534 for this field, "the AP disconnected the target STA after 20 sec on average". 
5. A valid SAE-Commit frame. 
6. A valid SAE-Confirm frame with the Send-Confirm field equal to 0. 
7. As with (6), but the Send-Confirm field’s value is set to 2.

As with the Management frames module, the present one uses the same monitoring logic and is split in two different types of fuzzing procedures, namely, Standard and Extensive. For instance, the Authentication algorithm field is fuzzed using specific, cherry-picked values, including 0, 1, 2, and 200, and not random ones generated by Blab or otherwise. On the other hand, the Extensive mode concentrates on grindingly testing every valid SAE field combination, that is, every possible value in the range of 0 to 65535, making it far more time-consuming vis-à-vis the Standard mode.



## DoS attack module

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



## Vulnerabilities

So far, the fuzzer managed to identify the following CVE IDs, by exploiting different Management frames: 

| CVE IDs                                                                          | Vulnerable Devices/Chipsets | WPA2/WPA3-SAE | Status   | Score |
|----------------------------------------------------------------------------------|-----------------------------|---------------|----------|-------|
| [CVE-2022-32654](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32654)  | mt5221/mt7603/mt7613<br />mt7615/mt7622/mt7628<br />mt7629/mt7663/mt7668<br />mt7682/mt7686/mt7687<br />mt7697/mt7902/mt7915<br />mt7916/mt7921/mt7933<br />mt7981/mt7986/mt8167S<br />mt8175/mt8362A/mt8365<br />mt8385/mt8518S/mt8532<br />mt8695/mt8696/mt8788                         | Both          | Published | 6.7 (Medium) |
| [CVE-2022-32655](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32655)  | mt5221/mt7603/mt7613<br />mt7615/mt7622/mt7628<br />mt7629/mt7663/mt7668<br />mt7682/mt7686/mt7687<br />mt7697/mt7902/mt7915<br />mt7916/mt7921/mt7933<br />mt7981/mt7986/mt8167S<br />mt8175/mt8362A/mt8365<br />mt8385/mt8518S/mt8532<br />mt8695/mt8696/mt8788                         | Both          | Published |6.7 (Medium)  |
| [CVE-2022-32656](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32656)  | mt5221/mt7603/mt7613<br />mt7615/mt7622/mt7628<br />mt7629/mt7663/mt7668<br />mt7682/mt7686/mt7687<br />mt7697/mt7902/mt7915<br />mt7916/mt7921/mt7933<br />mt7981/mt7986/mt8167S<br />mt8175/mt8362A/mt8365<br />mt8385/mt8518S/mt8532<br />mt8695/mt8696/mt8788                         | Both          | Published | 6.7 (Medium) |
| [CVE-2022-32657](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32657)  | mt7603/mt7613/mt7615<br />mt7622/mt7628/mt7629<br />mt7915/mt7916/mt7981<br />mt7986                         | Both          | Published | 6.7 (Medium)     |
| [CVE-2022-32658](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32658)  | mt7603/mt7613/mt7615<br />mt7622/mt7628/mt7629<br />mt7915/mt7916/mt7981<br />mt7986                         | Both          | Published | 6.7 (Medium)     |
| [CVE-2022-32659](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32659)  | mt7603/mt7613/mt7615<br />mt7622/mt7628/mt7629<br />mt7915/mt7916/mt7981<br />mt7986/mt8518s/mt8532                         | Both          | Published | 6.7 (Medium)     |
| [CVE-2022-46740](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-46740)  | WS7100-20                   | Both          | Published | 6.5 (Medium)     |

We would like also to thank the MediaTek and Huawei security teams, for acknowledging and fixing these security issues, as stated in the following two security advisories: [MediaTek](https://corp.mediatek.com/product-security-acknowledgements) and [Huawei](https://www.huawei.com/en/psirt/security-advisories/2022/huawei-sa-dosvihswr-8f632df1-en).

Moreover, by following the methodology of the work titled ["How is your Wi-Fi connection today? DoS attacks on WPA3-SAE"](https://www.sciencedirect.com/science/article/pii/S221421262100243X), the fuzzer can identify the same SAE vulnerabilities which are linked to the below CVE IDs:

| CVE IDs                                                                          | Vulnerable Devices/Chipsets | WPA2/WPA3-SAE | Status   | Score |
|----------------------------------------------------------------------------------|-----------------------------|---------------|----------|-------|
| [CVE-2021-37910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-37910)  | All ASUS RX-based models | WPA3-SAE | Published | 5.3 (medium)     |
| [CVE-2021-40288](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40288)  | AX10v1             | WPA3-SAE | Published | 7.5 (high)     |
| [CVE-2021-41753](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41753)  | DIR-x1560/DIR-X6060 | WPA3-SAE | Published | 7.5 (high)     |
| [CVE-2021-41788](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41788)  | mt7603E/mt7612/mt7613<br />mt7615/mt7622/mt7628<br />mt7629/mt7915| WPA3-SAE           | Published | 7.5 (high)     |



## Related Work

The interested readers are referred to the below publications regarding the methodology used to build [WPAxFuzz](https://www.mdpi.com/2410-387X/6/4/53). Note that the paper titled ["How is your Wi-Fi connection today? DoS attacks on WPA3-SAE"](https://www.sciencedirect.com/science/article/pii/S221421262100243X) published in the international Journal of Information Security and Applications (JISA), Elsevier has received the Dr KW Wong Annual Best Paper Award for 2022. The announcement can be found at: https://www.sciencedirect.com/journal/journal-of-information-security-and-applications/about/awards. Overall, the methodology detailed in the JISA paper is expanded in the WPAxFuzz publication.

```
@article{kampourakis2022wpaxfuzz,
  title={WPAxFuzz: Sniffing Out Vulnerabilities in Wi-Fi Implementations},
  author={Kampourakis, Vyron and Chatzoglou, Efstratios and Kambourakis, Georgios and Dolmes, Apostolos and Zaroliagis, Christos},
  journal={Cryptography},
  volume={6},
  number={4},
  pages={53},
  year={2022},
  publisher={MDPI}
}
```
```
@article{chatzoglou2022your,
  title={How is your Wi-Fi connection today? DoS attacks on WPA3-SAE},
  author={Chatzoglou, Efstratios and Kambourakis, Georgios and Kolias, Constantinos},
  journal={Journal of Information Security and Applications},
  volume={64},
  pages={103058},
  year={2022},
  publisher={Elsevier}
}
```



## License

MIT License

Copyright (c) 2022-2023 Vyron Kampourakis (Management frames, Control frames, Data frames and DoS tools)<br />
Copyright (c) 2022 Apostolos Dolmes (SAE Exchange tool)<br />
Copyright (c) 2022-2023 Efstratios Chatzoglou (Methodology)


## Contact

Efstratios Chatzoglou -  efchatzoglou@gmail.com  <br />
Vyron Kampourakis -  byrkam@gmail.com  


## Acknowledgments

We would like to thank all the vendors we contacted and reported these attacks, along with the retrieved bug bounties we received. Also, we would like to give some acknowledgement [the README template repo](https://github.com/othneildrew/Best-README-Template), which helped us to create this README file and [logo.com](https://logo.com/), which allowed us to create the WPAxFuzz tool logo.


<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/badge/Contributors-3-brightgreen?style=for-the-badge
[contributors-url]: https://github.com/efchatz/WPAxFuzz/contributors
[stars-shield]: https://img.shields.io/badge/Stars-55-blue?style=for-the-badge
[stars-url]: https://github.com/efchatz/WPAxFuzz/stargazers
[forks-shield]: https://img.shields.io/badge/Forks-3-blue?style=for-the-badge
[forks-url]: https://github.com/efchatz/WPAxFuzz/network/members
[issues-shield]: https://img.shields.io/badge/Issues-1-lightgrey?style=for-the-badge
[issues-url]: https://github.com/efchatz/WPAxFuzz/issues
[license-shield]: https://img.shields.io/github/license/othneildrew/Best-README-Template.svg?style=for-the-badge
[license-url]: https://github.com/efchatz/WPAxFuzz/blob/main/LICENSE
[Python.py]: https://img.shields.io/badge/Python-3.7-blue
[Python-url]: https://www.python.org/
[Scapy]: https://img.shields.io/badge/scapy-2.4.3-blue
[Scapy-url]: https://github.com/secdev/scapy
[Nmap]: https://img.shields.io/badge/Nmap-7.93-blue
[Nmap-url]: https://nmap.org/
[Blab]: https://img.shields.io/badge/Blab-1.0-blue
[Blab-url]: https://gitlab.com/akihe/blab/-/tree/master
