import json
 

config = json.load(open('src/config.json', 'r'))

targeted_AP = config["AP_info"]["AP_MAC_ADDRESS"]
att_interface = config["ATT_interface_info"]["ATTACKING_INTERFACE"]
targeted_STA = config["STA_info"]["TARGETED_STA_MAC_ADDRESS"]
real_ap_ssid = config["AP_info"]["AP_SSID"]

