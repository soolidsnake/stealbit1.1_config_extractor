from struct import *
import binascii
import pefile
import re
import yara
from optparse import OptionParser
import os
import sys

def extract_config(file):

    print("\033[1;31m[+] FILE: {} \033[0m".format(file))
    rule = yara.compile(source='rule foo: bar {strings: $a = {8B C1 83 E0 0F 8A 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 83 F9 ?? 72 E9 E8} condition: $a and uint16(0) == 0x5A4D}')
    data = open(file, 'rb').read() 

    offset = rule.match(data=data)

    if not offset:
        print("[-] Error signature not found")
        print("-"*100)
        return 0

    pe =  pefile.PE(file)
    for section in pe.sections:
        if section.Name.replace(b'\x00', b'') == b'.data':
            break

    offset = offset[0].strings[0][0]

    key = data[offset + 7:offset + 7 + 4]
    key = (unpack("<I", key)[0]) - pe.OPTIONAL_HEADER.ImageBase - (section.VirtualAddress - section.PointerToRawData)
    config_encrypted = data[offset + 13:offset + 13 + 4]
    
    config_encrypted = (unpack("<I", config_encrypted)[0]) - pe.OPTIONAL_HEADER.ImageBase - (section.VirtualAddress - section.PointerToRawData)
    config = ''

    for i in range(0, 0x7c):
        config += chr(data[config_encrypted + i] ^ data[key + (i&0xf)])

    print("extracted config : ", ' '.join(config[8:].split('\x00')))
    print("-"*100)
    return 1



if __name__ == '__main__': 
    print("Author: @Soolidsnake")
    print("""
 _____ _             _______ _ _   __    __                     __ _                   _                  _             
/  ___| |           | | ___ (_) | /  |  /  |                   / _(_)                 | |                | |            
\ `--.| |_ ___  __ _| | |_/ /_| |_`| |  `| |    ___ ___  _ __ | |_ _  __ _    _____  _| |_ _ __ __ _  ___| |_ ___  _ __ 
 `--. \ __/ _ \/ _` | | ___ \ | __|| |   | |   / __/ _ \| '_ \|  _| |/ _` |  / _ \ \/ / __| '__/ _` |/ __| __/ _ \| '__|
/\__/ / ||  __/ (_| | | |_/ / | |__| |___| |_ | (_| (_) | | | | | | | (_| | |  __/>  <| |_| | | (_| | (__| || (_) | |   
\____/ \__\___|\__,_|_\____/|_|\__\___(_)___/  \___\___/|_| |_|_| |_|\__, |  \___/_/\_\\__|_|  \__,_|\___|\__\___/|_|   
                                                                      __/ |                                             
                                                                     |___/                                              
""")
    parser = OptionParser()
    success = 0
    parser.add_option("-f", "--file", dest="filename", help="file", metavar="file")
    parser.add_option("-d", "--dir", dest="dirname", help="directory", metavar="dir")
    (options, args) = parser.parse_args()
    file_path = options.filename
    dir_path = options.dirname
    if file_path is None and dir_path is None: 
        parser.print_help()
        sys.exit(1)
        
    if file_path and os.path.isfile(file_path): 
        extract_config(file_path) 
    
    if dir_path and os.path.isdir(dir_path): 
        files = [] 
        for (dirpath, dirnames, filenames) in os.walk(dir_path): 
            for file in filenames:
                success += extract_config(os.path.join(dirpath, file))
                
            print("[+] extracted config of {} files".format(success))