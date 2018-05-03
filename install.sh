#!/bin/bash

#curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && sudo python get-pip.py

virtualenv venv || exit 1
# Upgrade pip (ssl issue); shouldn't be needed long-term
. venv/bin/activate || exit 1

#pip install -r requirements.txt

pip install .
