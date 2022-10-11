from datetime import datetime
import subprocess


class LogFiles:
    def __init__(self):
        now = datetime.now()
        self.folder_name_mngmt = datetime.now().strftime("fuzz_mngmt_frames")
        self.folder_name_ctrl = datetime.now().strftime("fuzz_ctrl_frames")
        self.folder_name_data = datetime.now().strftime("fuzz_data_frames")
        self.folder_path_mngmt = 'Logs/' + self.folder_name_mngmt
        self.folder_path_ctrl = 'Logs/' + self.folder_name_ctrl
        self.folder_path_data = 'Logs/' + self.folder_name_data
        self.is_alive_path_mngmt = self.folder_path_mngmt + datetime.now().strftime(f"/Aliveness_check_%d-%m-%y__%H:%M:%S")
        self.is_alive_path_ctrl = self.folder_path_ctrl + datetime.now().strftime(f"/Aliveness_check_%d-%m-%y__%H:%M:%S")
        self.is_alive_path_data = self.folder_path_data + datetime.now().strftime(f"/Aliveness_check_%d-%m-%y__%H:%M:%S")
        self.frames_till_disr_mngmt = self.folder_path_mngmt + datetime.now().strftime(f"/frames_till_disr_%d-%m-%y__%H:%M:%S")
        self.frames_till_disr_ctrl = self.folder_path_ctrl + datetime.now().strftime(f"/frames_till_disr_%d-%m-%y__%H:%M:%S")
        self.frames_till_disr_data = self.folder_path_data + datetime.now().strftime(f"/frames_till_disr_%d-%m-%y__%H:%M:%S")
        subprocess.call(['mkdir -m 777 -p Logs'], shell = True)
        subprocess.call(['mkdir -m 777 -p ' + self.folder_path_mngmt], shell = True)
        subprocess.call(['mkdir -m 777 -p ' + self.folder_path_ctrl], shell = True)
        subprocess.call(['mkdir -m 777 -p ' + self.folder_path_data], shell = True)

    def logging_conn_loss(self, reason, write_to):
        f = open(write_to, "a")
        now = datetime.now()
        f.write(now.strftime("%H:%M:%S") + ": " + reason)
        f.close()
