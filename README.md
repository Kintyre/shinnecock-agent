


Install PIP (system wide)

    yum install python-pip

Or, more generically run:

    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
    sudo python get-pip.py


To install with virutalenv:

    pip install virtualenv
    virtualenv venv || exit 1
    souce venv/bin/activate || exit 1

Run installation

    pip install .


