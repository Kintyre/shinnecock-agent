Kintyre Speedtest Agent
-----------------------

An Internet speedtest monitoring utility for Splunk HEC.  Speedtest and other networking information
is captured and sent to a central Splunk instance via the Http Event Collector.  Scheduled
monitoring is handled by the OS scheduler of your choice (often cron or the Windows Scheduler).

The Splunk app and TA are in a different repository and will be available via Splunkbase.  This
app represents the core work surrounding the speed-test data collection and standalone agent
version.


Install
-------


Using pip:

    pip install kintyre-speedtest-agent

System-level install:  (For Mac/Linux)

    curl https://bootstrap.pypa.io/get-pip.py | sudo python - kintyre-speedtest-agent

_Note_: This will also install/update `pip` and work around some known TLS/SSL issues


Or, install via GIT....

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



Configure
---------

For the intial public release, the output is still hard-coded to a Kintyre dev server but this will
be replaced with a proper configuration file, but for any early adopters, please know this is quite
easy to change.  Simply edit the `output_to_hec()` function.



Credits
-------

This project internally uses:

 * [speedtest-cli](https://github.com/sivel/speedtest-cli) - for all Internet performance tests
 * [ifcfg](https://github.com/ftao/python-ifcfg) - For cross-platform network interface enumeration
 * [requets](http://docs.python-requests.org/en/master/) - For posting to the HEC endpoints
