Kintyre Speedtest Agent
-----------------------

[![Build Status](https://travis-ci.org/Kintyre/shinnecock-agent.svg?branch=master)](https://travis-ci.org/Kintyre/shinnecock-agent)
[![codecov](https://codecov.io/gh/Kintyre/shinnecock-agent/branch/master/graph/badge.svg)](https://codecov.io/gh/Kintyre/ksconf)
[![PyPI](https://img.shields.io/pypi/v/kintyre-speedtest-agent.svg)](https://pypi.org/project/kintyre-speedtest-agent/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/kintyre-speedtest-agent.svg)](https://pypi.org/project/kintyre-speedtest-agent/)


An Internet speedtest monitoring utility for Splunk HEC.  Speedtest and other networking information
is captured and sent to a central Splunk instance via the Http Event Collector.  Scheduled
monitoring is handled by the OS scheduler of your choice (often cron or the Windows Scheduler).

The Splunk app and TA are hosted in this [repository][shinnecock-splunk-app] and will be available
via Splunkbase.
The *Kintyre Speedtest App for Splunk* contains some example searches and visualizations of data
collected by this speedtest agent, and the *Kintyre Speedtest Add-on for Splunk* has an embedded
copy of the agent which can be conveniently used for collecting and forwarding speedtest data within
an existing Splunk infrastructure.


Install
-------


Using pip:

    pip install kintyre-speedtest-agent

System-level install:  (For Mac/Linux)

    curl https://bootstrap.pypa.io/get-pip.py | sudo python - kintyre-speedtest-agent

_Note_: This will also install/update `pip` and bypass some known TLS/SSL issues

If `pip` is not present or out of date on your Linux system, see the Python Packaging doc regarding
[Linux Package Managers][pip-on-linux], or more generally, [Installing Packages][pypa-tut].


Configure
---------

Configuration is handled by a configuration file stored in the user's home directory.
Run the `--register` command to bootstrap the configuration with appropriate values.
You may re-run this process at any time or edit the kintyre_speedtest.ini file directly.

Example registration command (using the Kintyre's dev server):

    kintyre-speedtest --register \
        --url http://splunkspeedtest.dev.kintyre.net:8088 \
        --token dbbcd446-f5e7-412b-a971-dae59167a72f

If your HEC is using HTTPS with a self-signed cert automatically generated by Splunk, then the
agent will fail with the error `[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed`.
To skip this for initial testing, add `--certs insecure` to the `--register` command shown
above.  Be sure to enable SSL certificate validation again for a long-term deployment.

*NOTE:* Be sure to run `--register` with the same OS user account used to schedule the execution
        of speedtest via your scheduler of choice.  Otherwise, the configuration file will not be
        found and the script will fail.


Upgrade
-------

Check what version you are running with

    kintyre-speedtest --version

If it's not the latest version, then upgrade using pip:

    pip install -U kintyre-speedtest-agent



What's collected
----------------

The following list documents the types of metrics collected by this agent. Be aware, this is
only a summary, not every specific data point.  It is possible some information similar to PII
could be collected such as a hostname with your name in it. Anyone with
security concerns should (1) run the script and see a dump of the information it collects, and (2)
make sure you trust the endpoint where you are sending this data.  If you have further questions,
please review the source code or feel free to ask questions by opening an issue on GitHub.

Data points:

 * Uniquely assigned UUID (If using the Splunk TA version, this is the forwarder's GUID.)
 * Speedtest metrics (The same data collected by the `speedtest-cli` project in '--json' output mode)
   * Bandwidth ratings
   * External IP address (as issued by the ISP)
   * Geo IP location
 * Local network interface information (varies by OS and installed CLI tools)
   * Device name
   * Wireless SSID, link quality, signal levels, etc.
   * Hardware address
   * Driver names and sometimes firmware info
 * Python info
   * Python version
   * Processor information
   * OS/platform name & version

A long-term goal of this project is to provide a means to enable/disable various portions of the
data collection process but this is not currently implemented.  If this is important to you, pull
requests are welcomed!



Developers
----------

If you wish to help with development, or simply install via git, we suggest installing into a
virtual environment that can be thrown away and recreated as necessary.  Pull-requests are welcome!

Prep:

    pip install virtualenv

Install:

    git clone https://github.com/Kintyre/shinnecock-agent.git
    cd shinnecock-agent || exit 1
    virtualenv venv || exit 1
    souce venv/bin/activate || exit 1
    pip install -r requirements.txt
    python setup.py install

Testing locally:

    # Assumes tox and multiple python versions have been installed (i.e., pyenv)
    tox

    # Accelerated test run bypassing the actual "SpeedTest" portion (save some bandwidth)
    tox -- --fake-it



Credits
-------

This project internally uses:

 * [speedtest-cli](https://github.com/sivel/speedtest-cli) - for all Internet performance tests
 * [ifcfg](https://github.com/ftao/python-ifcfg) - for cross-platform network interface enumeration
 * [requests](http://docs.python-requests.org/en/master/) - for posting to the HEC endpoints


[pip-on-linux]: https://packaging.python.org/guides/installing-using-linux-tools
[pypa-tut]: https://packaging.python.org/tutorials/installing-packages
[shinnecock-splunk-app]: https://github.com/Kintyre/shinnecock-splunk-app
