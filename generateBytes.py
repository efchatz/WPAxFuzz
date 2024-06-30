import os
import subprocess


def generate_bytes(num_of_bytes, mode):
        current_dir = os.getcwd()
        right_length = False
        if mode == 'standard':
            while not right_length:
                console_data = subprocess.Popen([f'''{current_dir}/blab -e 'output = octet octet = half_octet half_octet half_octet = [0-9] | [
A-F]' -n {num_of_bytes} '''], stdout=subprocess.PIPE, shell=True)
                console_data = [output.decode('ISO-8859-1').strip() for output in console_data.stdout.readlines()]
                all_bytes = str(console_data[0])
                # converts the "all_bytes" string of hexadecimal byte values into a list of integers
                bytes = [int(all_bytes[index: index + 2], 16) for index in range(0, len(all_bytes), 2)]
                if len(bytes) == num_of_bytes:
                    right_length = True
        elif mode == 'random':
            while not right_length:
                console_data = subprocess.Popen([f'''{current_dir}/blab -e 'output = octet+ octet = half_octet half_octet half_octet = [0-9] | [A-F]' '''], stdout=subprocess.PIPE, shell=True)
                console_data = [output.decode('ISO-8859-1').strip() for output in console_data.stdout.readlines()]
                all_bytes = str(console_data[0])
                bytes = [int(all_bytes[index: index + 2], 16) for index in range(0, len(all_bytes), 2)]
                if len(bytes) < 64:
                    right_length = True
        return bytes
