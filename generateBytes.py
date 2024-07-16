import os
import random
import subprocess

import gramfuzz


def generate_bytes(num_of_bytes, generator, mode):
    match generator:
        case 1:
            return blab(num_of_bytes, mode)
        case 2:
            return gramfuzzTool(num_of_bytes, mode)


def blab(num_of_bytes, mode):
    current_dir = os.getcwd()
    right_length = False

    match mode:
        case 'standard':
            while not right_length:
                console_data = subprocess.Popen([f'''{current_dir}/blab -e 'output = octet octet = half_octet half_octet half_octet = [0-9] | [
    A-F]' -n {num_of_bytes} '''], stdout=subprocess.PIPE, shell=True)
                console_data = [output.decode('ISO-8859-1').strip() for output in console_data.stdout.readlines()]
                all_bytes = str(console_data[0])
                # converts the "all_bytes" string of hexadecimal byte values into a list of integers
                bytes = [int(all_bytes[index: index + 2], 16) for index in range(0, len(all_bytes), 2)]
                if len(bytes) == num_of_bytes:
                    right_length = True
        case 'random':
            while not right_length:
                console_data = subprocess.Popen([
                    f'''{current_dir}/blab -e 'output = octet+ octet = half_octet half_octet half_octet = [0-9] | [A-F]' '''],
                    stdout=subprocess.PIPE, shell=True)
                console_data = [output.decode('ISO-8859-1').strip() for output in console_data.stdout.readlines()]
                all_bytes = str(console_data[0])
                bytes = [int(all_bytes[index: index + 2], 16) for index in range(0, len(all_bytes), 2)]
                if len(bytes) < 64:
                    right_length = True
    return bytes

def gramfuzzTool(num_of_bytes, mode):
    generator = gramfuzz.GramFuzzer()
    generator.load_grammar("octets_grammar.py")

    match mode:
        case 'standard':
            octets = generator.gen(cat="octets", num=num_of_bytes)
        case 'random':
            num_of_bytes = random.randint(1,64)
            octets = generator.gen(cat="octets", num=num_of_bytes)

    octets = [output.decode('ISO-8859-1') for output in octets]
    all_bytes = str(''.join(octets))
    return [int(all_bytes[index: index + 2], 16) for index in range(0, len(all_bytes), 2)]