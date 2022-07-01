from datetime import datetime
import subprocess


class LogFiles:
    def __init__(self):
        now = datetime.now()
        self.folder_name = datetime.now().strftime("fuzz_mngmt_frames")
        self.folder_path = 'Logs/' + self.folder_name
        self.deauth_path = self.folder_path + datetime.now().strftime(f"/Deauth_path_%d-%m-%y__%H:%M:%S")
        self.is_alive_path = self.folder_path + datetime.now().strftime(f"/Aliveness_check_%d-%m-%y__%H:%M:%S")
        self.frames_till_disr = self.folder_path + datetime.now().strftime(f"/frames_till_disr_%d-%m-%y__%H:%M:%S")
        subprocess.call(['mkdir -m 777 -p Logs'], shell = True)
        subprocess.call(['mkdir -m 777 -p ' + self.folder_path], shell = True)

    def logging_conn_loss(self, reason, write_to):
        f = open(write_to, "a")
        now = datetime.now()
        f.write(now.strftime("%H:%M:%S") + ": " + reason)
        f.close()
