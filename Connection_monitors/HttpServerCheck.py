import threading
import time
import requests

URL_HOST = "http://192.168.2.5:8080"

class HttpCheck(threading.Thread):

    def __init__(self):
        super(HttpCheck, self).__init__()

    def run(self):
        while True:
            self.check_host()

    def check_host(self):
        try:
            response = requests.get(URL_HOST, timeout=5)
            if response.status_code == 200:
                print("Server is up")
            else:
                print("Server is down")
        except requests.exceptions.RequestException as e:
            print(f"Failed to reach Host: {e}")