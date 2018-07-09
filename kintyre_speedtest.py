#!/usr/bin/env python

from __future__ import absolute_import, unicode_literals
import re
import sys
import json
import platform
import time
import locale
import random
import time
from subprocess import Popen, PIPE, list2cmdline
from collections import namedtuple

'''
try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser
'''


import ifcfg
import speedtest

default_encoding = locale.getpreferredencoding()

# To enable loads of noise!
# speedtest.DEBUG = True

JSON_FORMAT_VER = "0.3.4"

def cli_parser(cmd, breaker, regexes, group_by="id"):
    cregexes = []
    for regex in regexes:
        try:
            cre = re.compile(regex)
            cregexes.append(cre)
        except:
            sys.stderr.write("Failed to compile regex: {0}\n".format(regex))
            raise
    def f():
        try:
            # In Python 3.6 and later, we can set encoding via Popen
            proc = Popen(cmd, stdout=PIPE, stderr=PIPE)
        except OSError as e:
            # No such file or directory.  Utility not installed, moving on.
            if e.errno == 2:
                sys.stderr.write("Missing {0}\n".format(cmd[0]))
            else:
                raise
            return
        (stdout, stderr) = proc.communicate()
        stdout = stdout.decode(encoding=default_encoding, errors="replace")
        if proc.returncode != 0:
            sys.stderr.write("FAILED: rc={1}  {0}\n".format(list2cmdline(cmd), proc.returncode))
            return
        data = {}
        if breaker is None:
            chunks = [ stdout ]
        else:
            chunks = re.split(breaker, stdout)
        for (i, text) in enumerate(chunks):
            d = {}
            for regex in cregexes:
                m = regex.search(text)
                if m:
                    d.update(m.groupdict())
            if d:
                if group_by is None:
                    key = "default"
                else:
                    key = d.get(group_by, i)
                data[key] = d
        return data
    return f


get_macosx_network_hw = cli_parser(
    cmd=["networksetup", "-listallhardwareports"],
    breaker=r"\n\n",
    regexes=[
        r"\bDevice:\s+(?P<device>[a-z]+\d+)",
        r"\bHardware Port:\s+(?P<hardware_port>[^\r\n]+)",
        r"\bEthernet Address:\s+(?P<ethernet_address>[0-9a-f:]+)"],
    group_by="device")


get_macosx_airport = cli_parser(
    cmd=["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"],
    regexes=[
        r"\bSSID: (?P<SSID>[^\r\n]+)",
        r"\bBSSID: (?P<BSSID>\S+)",
        r"\bMCS: (?P<MCS>\d+)",
        r"\bagrCtlRSSI: (?P<agr_ctl_rssi>-?\d+)",
        r"\bagrExtRSSI: (?P<agr_ext_rssi>-?\d+)",
        r"\bagrCtlNoise: (?P<agr_ctl_noise>-?\d+)",
        r"\bagrExtNoise: (?P<agr_ext_noise>-?\d+)",
        r"\blastTxRate: (?P<last_tx_rate>\d+)",
        r"\bchanel: (?P<chanel>\d+)",
        r"\bmaxRate: (?P<max_rate>\d+)",
    ], breaker=None,  group_by=None)


get_linux_iwconfig = cli_parser(
    cmd=["iwconfig"],
    breaker=r"\n\n",
    regexes=[
        r"^(?P<device>[a-z]+\d+)  \s+",
        r"\b(?P<device_type>IEEE 802.11[a-z]+)",
        r'\bBit Rate[:=](?P<bit_rate_mbps>\d+) Mb/s',
        r'\bESSID:"(?P<SSID>[^\r\n"]+)"',
        r"Link Quality=(?P<link_quality>\d+/\d+)",
        r"Signal level=(?P<signal_level_dBm>-?\d+) dBm",
        r"Signal level=(?P<signal_level>\d+/\d+)",
    ],
    group_by="device")

get_linux_lshw = cli_parser(
    cmd=["lshw", "-class", "network"],
    breaker=r"[\r\n]+\s+\*-network",
    regexes=[
        r"\blogical name: (?P<device>\S+)",
        r"\s+description: (?P<description>[^\r\n]+)",
        r"\s+capabilities: (?P<capabilities>[^\r\n]+)",
        r"\s+configuration: (?P<configuration>[^\r\n]+)",
        r"\bdriver=(?P<driver>\S+)",
        r"\bdriverversion=(?P<driver_version>\S+)",
    ],
    group_by="device")


get_windows_netsh = cli_parser(
    ["netsh", "WLAN", "show", "interfaces"],
    breaker=r"\n\n",       # Unsure.  Need to find with 2 WLAN cards
    regexes=[
        r"\s+Name\s+: (?P<Name>[^\r\n]+)",
        r"\s+Description\s+: (?P<Description>[^\r\n]+)",
        r"\s+Physical address\s+: (?P<mac>[0-9a-fA-F:]+)",
        r"\s+SSID\s+: (?P<SSID>[^\r\n]+)",
        r"\s+BSSID\s+: (?P<BSSID>[^ ]+)",
        r"\s+Channel\s+: (?P<Channel>\d+)",
        r"\s+Radio Type\s+: (?P<radio_type>\S+)",
        r"\s+Receive rate \(Mbps\)\s*: (?P<receive_rate_mbps>\d+)",
        r"\s+Transmit rate \(Mbps\)\s*: (?P<transmit_rate_mbps>\d+)",
        r"\s+Signal\s+: (?P<signal_percent>\d+)%",
    ],
    group_by="mac")


def run_speedtest(ip=None):
    try:
        st = speedtest.Speedtest(source_address=ip)
    except speedtest.ConfigRetrievalError as e:
        if ip:
            sys.stderr.write("Unable to run speedtest for {} because {}\n".format(ip, e))
        else:
            sys.stderr.write("Unable to run speedtest because {}\n".format(e))
        return None
    d = {}
    st.get_best_server()
    start = time.time()
    st.download()
    end = time.time()
    d["download_duration"] = "{0:01.3f}".format(end - start)
    start = end
    st.upload()
    end = time.time()
    d["upload_duration"] = "{0:01.3f}".format(end - start)
    data = st.results.dict()
    data.update(d)
    return data

def output_to_scriptedinput(event):
    json.dump(event, sys.stdout)
    sys.stdout.write("\n")

def output_to_hec(event):
    import requests
    import socket
    endpoint = "http://splunkspeedtest.dev.kintyre.net:8088"
    token = "dbbcd446-f5e7-412b-a971-dae59167a72f"
    #
    url =  "{0}/services/collector/event".format(endpoint)
    headers = { "Authorization" : "Splunk " + token }
    payload = {
        "host" : socket.gethostname(),
        "event" : event,
    }
    r = requests.post(url, headers=headers, data=json.dumps(payload))
    if not r.ok:
        sys.stderr.write("Pushing to HEC failed.  url={0}, error={0}\n". format(url, r.text))


def add_platform_info(d):
    def non_empty(x):
        if isinstance(x, (list, tuple)):
            for i in x:
                if non_empty(i):
                    return True
            return False
        elif x:
            return True
        else:
            return False
    p = {}
    p["platform"] = platform.platform()
    p["processor"] = platform.processor()
    system = p["system"] = platform.system()
    if system == "Linux":
        (dist, version, linux_id) = platform.linux_distribution()
        p["linux"] = {
            "dist": dist,
            "version": version,
            "id": linux_id}
    elif system == "Darwin":
        (release, versioninfo, machine) = platform.mac_ver()
        p["mac"] = {"release": release,
                    "machine": machine}
    elif system == "Windows":
        (release, version, csd, ptype) = platform.win32_ver()
        p["win"] = {
            "release": release,
            "version": version,
            "csd": csd}
    elif system == "Java":
        # Just dump it... very unlikely
        p["java"] = platform.java_ver()
    # Everybody has a uname!
    (system, node, release, version, machine, processor) = platform.uname()
    p["uname"] = dict(
        system=system,
        node=node,
        release=release,
        version=version,
        machine=machine,
        processor=processor
    )
    plat = d["platform"] = {}
    for (k,v) in list(p.items()):
        if non_empty(v):
            plat[k] = v



InterfaceInfo = namedtuple("InterfaceInfo", ("ip", "dev", "meta"))


def _filter_interface_attrs(ifcfg_if, **extra):
    """ Keep only some of the ifcfg attributes (prevent info leakage by being explicit.) """
    # Todo:  See if there are any other interesting goodies provided by Windows
    # Todo:  Capture the "Description" field from ipconfig; extend Windows class in ifcfg
    d = {}
    for k in ("device", "ether", "status", "mtu", "txbytes", "rxbytes"):
        if k in ifcfg_if:
            d[k] = ifcfg_if[k]
    d["v"] = JSON_FORMAT_VER
    d.update(**extra)
    return InterfaceInfo(ifcfg_if['inet'], ifcfg_if['device'], d)


def find_interfaces(whitelist=None):
    try:
        interfaces = ifcfg.interfaces()
    except Exception as e:
        sys.stderr.write("Unable to get interface info.  Falling back to simple output. "
                         "Error: {0}\n".format(e))
        yield InterfaceInfo(None, None, dict(v=JSON_FORMAT_VER, _error="ifcfg failed: {}".format(e)))
        return

    if not interfaces:
        yield InterfaceInfo(None, None, dict(v=JSON_FORMAT_VER,
                                             _error="no output from ifcfg.interface()"))
        return

    for name, interface in interfaces.items():
        if whitelist:
            if name not in whitelist:
                continue

        # Skip loopback adapter
        if name.startswith("lo"):
            continue
        if interface.get("status", None) == "inactive":
            continue
        if interface["inet"] is None:
            continue
        yield _filter_interface_attrs(interface)


def find_matching_interfaces(selected, whitelist=None, blacklist_pattern=None):
    if selected == "default":
        dflt = ifcfg.default_interface()
        if dflt:
            return [ _filter_interface_attrs(dflt) ]
        else:
            sys.stderr.write("No default interface found.  Randomly picking one.\n")
            selected = "random"

    interfaces = list(find_interfaces(whitelist))

    # Loop over interfaces.  eliminate blacklist matches.
    #   default:
    #       "(u|)tun\d+"       add match for PPP adapter for windows too

    if blacklist_pattern:
        blacklist_pattern = re.compile(blacklist_pattern)

        interfaces2 = [ i for i in interfaces if not blacklist_pattern.match(i.dev) ]
        # ToDo:  Debug log:  show which interfaces were blacklisted...
        # ToDo:  Check to see if ALL interfaces have been eliminated by this filter.  (recover by passing in NO ip?)
        if len(interfaces) != len(interfaces2):
            sys.stderr.write("Blacklist filter eliminated {} interface devices\n".format(
                len(interfaces)-len(interfaces2)))
            interfaces = interfaces2

    if not interfaces:
        return InterfaceInfo(None, None, dict(_error="No non-blacklisted interfaces found."))
    if selected == "all":
        return interfaces
    elif selected == "random":
        return [ random.choice(interfaces) ]
    else:
        raise RuntimeError("Unknown selection type of {!r}".format(selected))



def main(interfaces, output=output_to_hec):
    sys.stderr.write("DEBUG:  iterfaces for testing: {0!r}\n".format(interfaces))

    net_info = get_macosx_network_hw()
    sys.stderr.write("DEBUG:  get_macosx_hardware() returns: {0!r}\n".format(net_info))

    win_info = get_windows_netsh()
    sys.stderr.write("DEBUG:  get_windows_netsh() returns: {0!r}\n".format(win_info))

    iwconfig_info = get_linux_iwconfig()
    sys.stderr.write("DEBUG:  get_linux_iwconfig() returns: {0!r}\n".format(iwconfig_info))

    lshw_info = get_linux_lshw()
    sys.stderr.write("DEBUG:  get_linux_lshw() returns: {0!r}\n".format(lshw_info))

    for if_ in interfaces:
        info = if_.meta
        try:
            mac = None
            sys.stderr.write("Speed testing on interface {0} (ip={1})\n".format(if_.dev, if_.ip))
            results = run_speedtest(if_.ip)
            if "device" in info:
                results["dev"] = info.pop("device")
            if "ether" in info:
                mac = results["address"] = info.pop("ether")
            if info:
                results["meta"] = info

            # Add MacOSX hardware info, if available.  (Indicate LAN vs Wireless)
            if net_info and if_.dev in net_info:
                hw_port = net_info[if_.dev].get("hardware_port")
                if hw_port:
                    results["osx_hw_port"] = hw_port
                    if hw_port.lower() == "wi-fi":
                        results["wlan"] = get_macosx_airport()["default"]

            if win_info and mac and mac in win_info:
                results["wlan"] = win_info[mac]

            # Add wireless info for Linux systems
            if iwconfig_info and if_.dev in iwconfig_info:
                results["wlan"] = iwconfig_info[if_.dev]

            if lshw_info and if_.dev in lshw_info:
                results["hardware"] = lshw_info[if_.dev]

            try:
                add_platform_info(results)
            except Exception as e:
                sys.stderr.write("Failed to get platform info: {0} \n".format(e))

            # Add python version info
            # Todo: Figure out what bits we really want to capture.
            results["py"] = sys.version

            # Add other Linux info for
            results["v"] = JSON_FORMAT_VER
            o = json.dumps(results)
            sys.stderr.write("DEBUG:   Payload:  {0}\n".format(o))
            output(o)
        except Exception as e:
            sys.stderr.write("Failure for ip {0}: {1}\n".format(if_.ip, e))

'''
def load_config(path):
    cp = ConfigParser()
    cp.read(path)
    uuid = cp.get("default", "uuid")
'''



def cli():
    from argparse import ArgumentParser

    parser = ArgumentParser(description="Kintyre speedtest agent")
    parser.add_argument("--version", "-V", action="version", version=JSON_FORMAT_VER)

    parser.add_argument("--interface", "-i",
                        nargs="+",
                        help="Name of interface(s) to speedtest.  No other interfaces will be "
                             "considered.  When used with --random then one of the provided "
                             "interfaces will be selected randomly.")

    parser.add_argument("--randomize",
                        type=int,
                        metavar="SECS",
                        help="Add a random delay before running the speedtest.  "
                             "This can avoid kicking off multiple test at the same moment.")

    ifslct = parser.add_mutually_exclusive_group()
    ifslct.add_argument("--random",
                        dest="interface_select",
                        action="store_const",
                        const="random",
                        help="Randomly pick and test a single interface to test on")
    ifslct.add_argument("--all",
                        dest="interface_select",
                        action="store_const",
                        const="all",
                        help="Test against all usable interfaces.")
    ifslct.add_argument("--default",
                        dest="interface_select",
                        action="store_const",
                        const="default",
                        help="Run speedtest on the interface with a default gateway.  (This is the "
                             "default behavior, unless the --interface option is provided)")

    parser.add_argument("--fake-it",
                        action="store_true",
                        help="Disable speedtest functionality and return a bogus payload instead."
                             "ONLY useful for testing.")


    args = parser.parse_args()


    if args.fake_it:
        def run_speedtest(ip=None):
            return { "FAKE_SPEEDTEST" : True, ip: ip }
        globals()["run_speedtest"] = run_speedtest

    print("interface:  {!r}".format(args.interface))
    if not args.interface_select:
        if args.interface:
            args.interface_select = "random"
        else:
            args.interface_select = "default"
    print("mode={}    interface:  {!r}".format(args.interface_select, args.interface))

    if args.randomize:
        delay = random.randint(0, args.randomize)
        print("Sleeping for {} seconds to randomize clocks".format(delay))
        time.sleep(delay)
    interfaces = find_matching_interfaces(args.interface_select, args.interface, r"^(u|v|)tun$")
    main(interfaces, output_to_hec)

if __name__ == '__main__':
    cli()
