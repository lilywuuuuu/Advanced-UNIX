#!/usr/bin/env python3 

import os
import sys

def main():
    if len(sys.argv) < 3:
        print("Usage: ./logger config.txt [-o file] [-p sopath] command [arg1 arg2 ...]")
        sys.exit(1)

    config_file = sys.argv[1]
    output_file = None
    shared_object_path = "./logger.so"

    i = 2 
    while i < len(sys.argv):
        if sys.argv[i] == "-o":
            if i + 1 < len(sys.argv):
                output_file = sys.argv[i + 1]
                i += 1
            else:
                print("Missing output file argument.")
                sys.exit(1)
        elif sys.argv[i] == "-p":
            if i + 1 < len(sys.argv):
                shared_object_path = sys.argv[i + 1]
                i += 1
            else:
                print("Missing shared object path argument.")
                sys.exit(1)
        else:
            break
        i += 1

    command = sys.argv[i:]
    if not os.path.isfile(config_file):
        print(f"Config file '{config_file}' not found.")
        sys.exit(1)

    if not os.path.isfile(shared_object_path):
        print(f"Shared object file '{shared_object_path}' not found.")
        sys.exit(1)

    os.environ["LD_PRELOAD"] = shared_object_path

    if output_file:
        os.environ["LOGGER_OUTPUT"] = output_file
    else: 
        os.environ["LOGGER_OUTPUT"] = "no_file"

    # set blacklists as environment variables
    blacklist = ""
    with open(config_file, 'r') as f:
        for line in f: 
            line = line.strip()
            if line.startswith('BEGIN'):
                if 'open-blacklist' in line:
                    bl = "OPEN_BL"
                elif 'read-blacklist' in line: 
                    bl = "READ_BL"
                elif 'write-blacklist' in line: 
                    bl = "WRITE_BL"
                elif 'connect-blacklist' in line: 
                    bl = "CONNECT_BL"
                elif 'getaddrinfo-blacklist' in line: 
                    bl = "GETADDRINFO_BL"
            elif line.startswith('END'):
                os.environ[bl] = blacklist
                blacklist = ""
            else:
                blacklist += line + " "

    os.execvp(command[0], command)

if __name__ == "__main__":
    main()
 