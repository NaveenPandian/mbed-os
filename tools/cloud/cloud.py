#! /usr/bin/env python2
"""
mbed SDK
Copyright (c) 2011-2013 ARM Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from __future__ import print_function
import sys
import os
import re
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from tools.options import get_default_options_parser

# Imports related to mbed build api
from mbed_cloud import CertificatesAPI
from argparse import ArgumentParser

def main():
    """Entry Point"""
    try:
        # Parse Options
        parser = ArgumentParser()

        parser.add_argument("-g", "--generate-credentials",
                            action="store_true",
                            dest="generate_credentials",
                            default=False,
                            help="Generates a developer certificate")
        
        parser.add_argument("-a", "--api-key",
                            dest="api_key",
                            default=None,
                            help="API key for Mbed Cloud")
        
        parser.add_argument("-s", "--api-host",
                            dest="api_host",
                            default=None,
                            help="API Hostname for Mbed Cloud")


        options = parser.parse_args()
        
        if options.api_key == None:
            print("[ERROR] No API key specified.")
            sys.exit(1)
            
        if options.api_host == None:
            print("[ERROR] No API host name specified.")
            sys.exit(1)
        
        if options.generate_credentials:
            generate_dev_credentials(options.api_key, options.api_host)
        
       
    except KeyboardInterrupt:
        print("\n[CTRL+c] exit")
    except Exception as exc:
        import traceback
        traceback.print_exc(file=sys.stdout)
        print("[ERROR] %s" % str(exc))
        sys.exit(1)
        
def generate_dev_credentials(api_key, api_host):
    
    try:
        api_config = {"api_key": api_key, "host": api_host}
        api = CertificatesAPI(api_config)
        
        # Create a new developer certificate
        print("Creating new developer certificate...")
        certificate = {
            "name": "dev_certificate_" + str(time.time())
        }
        new_certificate = api.add_developer_certificate(**certificate)
        print("Successfully created developer certificate with id: %r" % new_certificate.id)
        
        file = open("mbed_cloud_dev_credentials.c", "w+")
        file.write(new_certificate.header_file)
        file.close()
        print("Created developer credentials file at mbed_cloud_dev_credentials.c")
    
    except Exception as exc:
        print("[ERROR] Failed to create developer credentials \n %s" % str(exc))

if __name__ == '__main__':
    main()
