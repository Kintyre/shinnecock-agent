#!/bin/bash

#curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && sudo python get-pip.py

virtualenv venv || exit 1
# Upgrade pip (ssl issue); shouldn't be needed long-term

if [[ -f venv/bin/activate ]]
then
    . venv/bin/activate || exit 1
else # Try windows (mysys/cygwin)
    . venv/Scripts/activate || exit 1
fi
#pip install -r requirements.txt

pip install .
