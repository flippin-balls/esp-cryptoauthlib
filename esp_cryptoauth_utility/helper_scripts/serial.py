#!/usr/bin/env python
# Copyright 2020 Espressif Systems (Shanghai) Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
from sys import exit
import time
import subprocess
import serial
import sys
import re
try:
    import esptool
except ImportError:  # cheat and use IDF's copy of esptool if available
    idf_path = os.getenv('IDF_PATH')
    if not idf_path or not os.path.exists(idf_path):
        raise
    sys.path.insert(0, os.path.join(idf_path, 'components', 'esptool_py', 'esptool'))
    import esptool


class cmd_interpreter:
    """
    This class is for is the command line interaction with the secure_cert_mfg firmware for manufacturing.
    It executes the specified commands and returns its result.
    It is a stateless, thus does not maintain the current state of the firmware.
    """
    def __init__(self, port, baudrate=115200):
        # Serial Port settings
        self.port = serial.Serial()
        self.port.timeout = 2
        self.port.baudrate = baudrate
        self.port.port = port
        self.port.open()
        self.port.close()

    def wait_for_init(self):

        print('Wait for init')

        # Ensure the port is open
        if not self.port.isOpen():
            self.port.open()

        # Configuration variables
        p_timeout = 10  # Timeout for the entire initialization process
        expected_version_pattern = re.compile(rb'v\d+\.\d+\.\d+')  # Regex for vX.Y.Z

        # Initialization
        start_time = time.time()
        version_request_sent = False
        version_request_start_time = None

        while True:
            try:
                line = self.port.readline()
                if line != b'':
                    print(line.decode())

                # Check for initialization prompt or ongoing version request
                if b'Initializing Command line: >>' in line or version_request_sent:
                    if not version_request_sent:
                        print('Requesting version')
                        self.port.write(b'version')
                        version_request_sent = True
                        version_request_start_time = time.time()

                    # Check for expected version response
                    if expected_version_pattern.search(line):
                        print('Version reply received - CLI Initialized.')
                        return True

                    # Handle version reply timeout
                    elif (time.time() - version_request_start_time) > p_timeout:
                        print('version reply timed out')
                        return False

                # Handle overall timeout
                elif (time.time() - start_time) > p_timeout:
                    print('connection timed out')
                    return False
            except UnicodeError:
                print(line)

    def exec_cmd(self, port, command, args=None):
        ret = ''
        status = None
        self.port.timeout = 3
        self.port.baudrate = 115200
        self.port.write(command.encode() + b'\r')
        if args:
            time.sleep(0.1)
            if type(args) is str:
                args = args.encode()

            self.port.write(args)
            self.port.write(b'\0')

        while True:
            line = ''
            try:
                line = (self.port.readline()).decode()
                print(line)
            except UnicodeError:
                sys.stdout.flush()
                sys.stdout.write(line)

            if 'Status: Success' in line:
                status = True
            elif 'Status: Failure' in line:
                status = False
            if status is True or status is False:
                while True:
                    line = (self.port.readline()).decode()
                    if '>>' in line:
                        if status is True:
                            print(line)
                        break
                    else:
                        ret += line
                return [{'Status': status}, {'Return': ret}]


def _exec_shell_cmd(self, command):
    result = subprocess.Popen((command).split(), stdout=subprocess.PIPE)
    out, err = result.communicate()
    return out


def get_load_ram_esptool_args(stub_path):
    class EsptoolArgs(object):
        def __init__(self, attributes):
            for key, value in attributes.items():
                self.__setattr__(key, value)
    esptool_args = EsptoolArgs({
            'filename': stub_path
            })
    return esptool_args

def load_app_stub(port, baudrate, stub_path):
    if stub_path is None:
        raise ValueError('Stub path cannot be None')
    # Use ESPLoader as a context manager to ensure proper cleanup
    with esptool.cmds.detect_chip(port=port, baud=baudrate) as esp:
        print('Chip detected')
        esp.flash_spi_attach(0)

        esptool_args = get_load_ram_esptool_args(stub_path)
        start_time = time.time()
        esptool.cmds.load_ram(esp, esptool_args)
        end_time = time.time()
        print('Time required to load the app into the RAM'
              ' = {}s'.format(end_time - start_time))


def esp_cmd_check_ok(retval, cmd_str):
    if retval[0]['Status'] is not True:
        print((cmd_str + 'failed to execute'))
        print((retval[1]['Return']))
        exit(0)
