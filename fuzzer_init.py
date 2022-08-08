config = open('src/config.conf', 'r')
Lines = config.readlines()
for line in Lines:
    if 'AP_MAC_ADDRESS' in line:
        info = line.partition(' ')
        targeted_AP = info[len(info) - 1].strip().lower()
    elif 'ATTACKING_INTERFACE' in line:
        info = line.partition(' ')
        att_interface = info[len(info) - 1].strip()
    elif 'TARGETED_STA_MAC_ADDRESS' in line:
        info = line.partition(' ')
        targeted_STA = info[len(info) - 1].strip().lower()
    elif 'AP_SSID' in line:
        info = line.partition(' ')
        real_ap_ssid = info[len(info) - 1].strip()

