import json
 

config = json.load(open('src/config.json', 'r'))

targeted_AP = config["AP_info"]["AP_MAC_ADDRESS"]
AP_CHANNEL = config["AP_info"]["AP_CHANNEL"]
CHANNEL_DIFFERENT_FREQUENCY = config["AP_info"]["CHANNEL_DIFFERENT_FREQUENCY"]
AP_MAC_DIFFERENT_FREQUENCY = config["AP_info"]["AP_MAC_DIFFERENT_FREQUENCY"]
targeted_STA = config["STA_info"]["TARGETED_STA_MAC_ADDRESS"]
att_interface = config["ATT_interface_info"]["ATTACKING_INTERFACE"]
MONITORING_INTERFACE = config["ATT_interface_info"]["MONITORING_INTERFACE"]
PASSWORD = config["AP_info"]["PASSWORD"]
real_ap_ssid = config["AP_info"]["AP_SSID"]
