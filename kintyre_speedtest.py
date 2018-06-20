#!/usr/bin/env python

import re
import sys
import json
import platform
import time
from subprocess import Popen, PIPE, list2cmdline

import ifcfg
import speedtest

# To enable loads of noise!
# speedtest.DEBUG = True

JSON_FORMAT_VER = "0.3.0"

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
            proc = Popen(cmd, stdout=PIPE, stderr=PIPE)
        except OSError, e:
            # No such file or directory.  Utility not installed, moving on.
            if e.errno == 2:
                sys.stderr.write("Missing {0}\n".format(cmd[0]))
            else:
                raise
            return
        (stdout, stderr) = proc.communicate()
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
    breaker="[\r\n]+\s+\*-network",
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
    breaker="\n\n",       # Unsure.  Need to find with 2 WLAN cards
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
    except speedtest.ConfigRetrievalError, e:
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
    for (k,v) in p.items():
        if non_empty(v):
            plat[k] = v


def main(output=output_to_hec):
    if_for_testing = {}
    try:
        interfaces = ifcfg.interfaces()
    except Exception, e:
        sys.stderr.write("Unable to get interface info.  Falling back to simple output. "
                         "Error: {0}\n".format(e))
        results = run_speedtest(None)
        results["v"] = JSON_FORMAT_VER
        results["_error"] = "ifcfg failed"
        output(json.dumps(results))
        return

    for name, interface in interfaces.items():
        # Skip loopback adapter
        if name.startswith("lo"):
            continue
        if interface.get("status", None) == "inactive":
            continue
        if interface["inet"] is None:
            continue
        d = {}
        # Todo:  See if there are any other interesting goodies provided by Windows
        # Todo:  Capture the "Description" field from ipconfig; extend Windows class in ifcfg
        for k in ("device", "ether", "status", "mtu", "txbytes", "rxbytes"):
            if k in interface:
                d[k] = interface[k]
        if_for_testing[(interface['inet'], interface['device'])] = d

    sys.stderr.write("DEBUG:  iterfaces for testing: {0!r}\n".format(if_for_testing))

    net_info = get_macosx_network_hw()
    sys.stderr.write("DEBUG:  get_macosx_hardware() returns: {0!r}\n".format(net_info))

    win_info = get_windows_netsh()
    sys.stderr.write("DEBUG:  get_windows_netsh() returns: {0!r}\n".format(win_info))

    iwconfig_info = get_linux_iwconfig()
    sys.stderr.write("DEBUG:  get_linux_iwconfig() returns: {0!r}\n".format(iwconfig_info))

    lshw_info = get_linux_lshw()
    sys.stderr.write("DEBUG:  get_linux_lshw() returns: {0!r}\n".format(lshw_info))

    for ((ip,dev), info) in if_for_testing.items():
        try:
            mac = None
            sys.stderr.write("Speed testing on interface {0} (ip={1})\n".format(dev, ip))
            results = run_speedtest(ip)
            if "device" in info:
                results["dev"] = info.pop("device")
            if "ether" in info:
                mac = results["address"] = info.pop("ether")
            if info:
                results["meta"] = info

            # Add MacOSX hardware info, if available.  (Indicate LAN vs Wireless)
            if net_info and dev in net_info:
                hw_port = net_info[dev].get("hardware_port")
                if hw_port:
                    results["osx_hw_port"] = hw_port
                    if hw_port.lower() == "wi-fi":
                        results["wlan"] = get_macosx_airport()["default"]

            if win_info and mac and mac in win_info:
                results["wlan"] = win_info[mac]

            # Add wireless info for Linux systems
            if iwconfig_info and dev in iwconfig_info:
                results["wlan"] = iwconfig_info[dev]

            if lshw_info and dev in lshw_info:
                results["hardware"] = lshw_info[dev]

            try:
                add_platform_info(results)
            except Exception, e:
                sys.stderr.write("Failed to get platform info: {0} \n".format(e))

            # Add other Linux info for
            results["v"] = JSON_FORMAT_VER
            o = json.dumps(results)
            sys.stderr.write("DEBUG:   Payload:  {0}\n".format(o))
            output(o)
        except Exception, e:
            sys.stderr.write("Failure for ip {0}: {1}\n".format(ip, e))

if __name__ == '__main__':
    #main(output_to_scriptedinput)
    main(output_to_hec)
