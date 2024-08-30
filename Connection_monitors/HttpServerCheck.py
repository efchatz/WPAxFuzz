import os
import threading
from time import sleep
import requests

import settings
from Msgs_colors import bcolors


class HttpCheck(threading.Thread):

    def __init__(self, url, port):
        super(HttpCheck, self).__init__()
        self.url = url
        self.port = port
        self.url_host = 'http://'+self.url+':'+self.port

    def run(self):

        if self.mode == 'fuzzing':
            while True:
                sleep(1)
                response = self.check_host()
                if response == 200:
                    pass
                else:
                    settings.is_alive = False
                    print(f'\n{bcolors.FAIL}STA is unresponsive or the server is down{bcolors.ENDC}\n')
                    while True:
                        input(bcolors.WARNING + 'Reconnect the STA and press Enter to resume:\n' + bcolors.ENDC)
                        if self.check_host() == 200:
                            print(f'{bcolors.OKCYAN}Pausing for 20s and proceeding to the next subtype of frames{bcolors.ENDC}\n')
                            sleep(20)
                            settings.is_alive = True
                            settings.conn_loss = False
                            break
        elif self.mode == 'attacking':
            while True:
                sleep(1)
                response = self.check_host()
                if response == 200:
                    pass
                else:
                    settings.is_alive = False

    def check_host(self):
        try:
            response = requests.get(self.url_host, timeout=5)
            return response
        except requests.exceptions.RequestException as e:
            print(f"Failed to reach Host: {e}")
            os._exit(0)