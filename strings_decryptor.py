from struct import *
import binascii
import pefile
import yara
import re
import random
import base64
import json
from typing import Callable
from hashlib import sha1
from optparse import OptionParser
import os
import sys

def crypt(data: str, key: bytes) -> str:
    """RC4 algorithm"""
    x = 0
    box = list(range(256))
    for i in range(256):
        x = (x + int(box[i]) + int(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr((char) ^ box[(box[x] + box[y]) % 256]))

    return ''.join(out)

rule = yara.compile(source='rule foo: bar {strings: $a = {51 8B C6 BA ?? ?? ?? ?? 2B C1 50 51 51 8B 4D FC E8 4F 02 00 00 83 C4 10} condition: $a and uint16(0) == 0x5A4D}')

def decrypt_strings(file):
    
    print("\033[1;31m[+] FILE: {} \033[0m".format(file))

    data = open(file, 'rb').read() 

    key_offset = rule.match(data=data)

    if not key_offset:
        print("[-] Error signature not found")
        print("-"*100)
        return 0
    
    pe =  pefile.PE(file)
    for section in pe.sections:
        if section.Name.replace(b'\x00', b'') == b'.data':
            datasection = section

        if section.Name.replace(b'\x00', b'') == b'.bss':
            bssSection = section

    key_offset = key_offset[0].strings[0][0]
    key = data[key_offset + 4:key_offset + 4 + 4]
    key = (unpack("<I", key)[0]) - pe.OPTIONAL_HEADER.ImageBase - (datasection.VirtualAddress - datasection.PointerToRawData)
        

    string_encrypted = bssSection.PointerToRawData

    config = ''
    key = data[key:key+16]
    encrypted_list = data[string_encrypted:string_encrypted+0x600].split(b'\x00\x00')

    
    for encrypted in encrypted_list:
        if encrypted != b'':
            print(crypt(encrypted.lstrip(b'\x00'), key))
    
    print("-"*100)
    return 1
            
            
if __name__ == '__main__': 
    print("Author: @Soolidsnake")
    print("""
 _____ _             _______ _ _   __    __        _        _                             _                  _             
/  ___| |           | | ___ (_) | /  |  /  |      | |      (_)                           | |                | |            
\ `--.| |_ ___  __ _| | |_/ /_| |_`| |  `| |   ___| |_ _ __ _ _ __   __ _ ___    _____  _| |_ _ __ __ _  ___| |_ ___  _ __ 
 `--. \ __/ _ \/ _` | | ___ \ | __|| |   | |  / __| __| '__| | '_ \ / _` / __|  / _ \ \/ / __| '__/ _` |/ __| __/ _ \| '__|
/\__/ / ||  __/ (_| | | |_/ / | |__| |___| |_ \__ \ |_| |  | | | | | (_| \__ \ |  __/>  <| |_| | | (_| | (__| || (_) | |   
\____/ \__\___|\__,_|_\____/|_|\__\___(_)___/ |___/\__|_|  |_|_| |_|\__, |___/  \___/_/\_\\__|_|  \__,_|\___|\__\___/|_|   
                                                                     __/ |                                                 
                                                                    |___/                                                  
""")
    success = 0
    parser = OptionParser()
    parser.add_option("-f", "--file", dest="filename", help="file", metavar="file")
    parser.add_option("-d", "--dir", dest="dirname", help="directory", metavar="dir")
    (options, args) = parser.parse_args()
    file_path = options.filename
    dir_path = options.dirname
    if file_path is None and dir_path is None: 
        parser.print_help()
        sys.exit(1)
    if file_path and os.path.isfile(file_path): 
        decrypt_strings(file_path) 
    
    
    
    if dir_path and os.path.isdir(dir_path): 
        files = [] 
        for (dirpath, dirnames, filenames) in os.walk(dir_path): 
            for file in filenames:
                success += decrypt_strings(os.path.join(dirpath, file))
    
            print("[+] decrypted strings of {} files".format(success))