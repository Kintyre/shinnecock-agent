#!/usr/bin/env python

from __future__ import absolute_import, unicode_literals
import re
import sys
import os
import json
import platform
import functools
import time
import locale
import random
import time
from subprocess import Popen, PIPE, list2cmdline
from collections import namedtuple, OrderedDict
from io import open


def ConfigParser(*args, **kwargs):
    # Wonky lazy loader workaround (since this library is not required for splunk-embeded (TA)
    # version), but this class is used by multiple methods (so we can't simply inline the import)

    try:
        # New name under Python 3
        from configparser import ConfigParser as cp
    except ImportError:
        # Use backported config parser for Python 2.7 for proper Unicode support
        from backports.configparser import ConfigParser as cp
    # All future accesses of 'ConfigParser' will go directly to this class
    globals()["ConfigParser"] = cp
    return cp(*args, **kwargs)


import ifcfg
import speedtest

default_encoding = locale.getpreferredencoding()


def generate_agent_uuid():
    import uuid
    u = uuid.uuid4()
    return str(u)


JSON_FORMAT_VER = "0.3.8"

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
    sys.stderr.write("DEBUG:   Payload:  {0}\n".format(json.dumps(event)))
    json.dump(event, sys.stdout)
    sys.stdout.write("\n")


def output_to_hec(conf, event, source=None):
    import requests
    import socket
    url = "{0}/services/collector/event".format(conf.endpoint_url)
    headers = { "Authorization" : "Splunk " + conf.endpoint_token }
    event = dict(event)
    event["hostname"] = socket.gethostname()
    agent_info = {}
    if conf.get("agent_name", None):
        agent_info["name"] = conf.agent_name
    if conf.get("agent_org", None):
        agent_info["org"] = conf.agent_org
    if conf.get("agent_description", None):
        agent_info["description"] = conf.agent_description
    if agent_info:
        event["agent"] = agent_info
    payload = {
        "host" : conf.uuid,
        "event" : event,
    }
    if source:
        payload["source"] = source
    sys.stderr.write("DEBUG:  Payload --> {0}  :  {1}\n".format(url, json.dumps(event)))
    r = requests.post(url, headers=headers, data=json.dumps(payload))
    if not r.ok:
        sys.stderr.write("Pushing to HEC failed.  url={}, error={}\n". format(url, r.text))
        return False
    else:
        sys.stderr.write("   Status code = {}\n".format(r.status_code))
        return True


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
            output(results)
        except Exception as e:
            sys.stderr.write("Failure for ip {0}: {1}\n".format(if_.ip, e))
            # For debugging
            # XXX:  Find a way to publish error messages back to HEC
            import traceback
            traceback.print_exc()




NotSet = object()

class _ConfigOption(object):
    def __init__(self, name, env=None, cli=None, ini=None, help=None, default=NotSet,
                 validator=None, prompt=False):
        self.name = name
        self.env = env
        self.cli = cli
        self.ini = ini
        self.help = help
        self.prompt = prompt

        self._default = default
        self._validator = validator

        # Checks
        if ini and (not isinstance(ini, tuple) or len(ini) != 2):
            raise ValueError("Expecting ini to be in a tuple in the form of (section,option), but "
                             "given {!r}".format(ini))
        if validator and not callable(validator):
            raise ValueError("Validator should be callable.  Instead {!r} given".format(validator))

    @property
    def default(self):
        if self._default is NotSet:
            return NotSet
            # ???  Best approach here?  This feels like an inappropriate use for AttributeError, as hasattr(o, "default") will certainly return True
            # raise AttributeError("No default value set for {}".format(self.name))
        elif callable(self._default):
            return self._default()
        else:
            return self._default

    @property
    def ini_section(self):
        if self.ini:
            return self.ini[0]
        return None

    @property
    def ini_option(self):
        if self.ini:
            return self.ini[1]
        return None


class ConfigManager(object):
    """ Resolution order:

        (1) Command line (always wins)
        (2) Environmental variables
        (3) Config file  [[ ONLY READ/WRITE layer]]
        (4) Default value (ConfigOption)
        (5) Default value (passed to get())
    """
    __options = OrderedDict()

    @classmethod
    def add_config(cls, *args):
        for co in args:
            cls.__options[co.name] = co

    __slots__ = ( "_cached_values", "_cfg_file_cache", "_writeback_keys", "_ini_file",
                  "_env", "_cli_args")

    def __init__(self, ini_file, env=None, cli_args=None):
        self._cached_values = {}
        self._cfg_file_cache = None
        self._writeback_keys = set()
        self._ini_file = ini_file
        self._env = env or os.environ
        self._cli_args = cli_args

    def __del__(self):
        if self._writeback_keys:
            sys.stderr.write("Warning:  Discarding {:d} unsaved changes to {}\n".format(
                len(self._writeback_keys), self._ini_file))

    def __getattr__(self, item):
        if item in self.__slots__:
            return getattr(self, item)
        return self.get(item, NotSet)

    def __setattr__(self, item, value):
        if item in self.__slots__:
            object.__setattr__(self, item, value)
        else:
            self.set(item, value)
        return item

    def set(self, item, value):
        if item not in self.__options:
                raise AttributeError("No attribute named {!r}.  New attributes must be "
                                     "registered via add_config() ".format(item))
        self._cached_values[item] = value
        self._writeback_keys.add(item)

    def get(self, attr, default=None):
        # Never cache a 'default' value passed to this function.
        if attr in self._cached_values:
            return self._cached_values[attr]
        else:
            try:
                value = self._get(attr)
            except AttributeError as e:
                if default is NotSet:
                    raise e
                else:
                    return default
            # _get() was successful; cache return value
            self._cached_values[attr] = value
            return value

    def _get(self, attr):
        # Layer 1:  Command line
        co = self.__options[attr]
        if co.cli and self._cli_args and hasattr(self._cli_args, co.cli):
            val = getattr(self._cli_args, co.cli)
            if val:
                return val
        # Layer 2:  Environmental variables
        if co.env and co.env in self._env:
            val = self._env[co.env]
            if val:
                return val
        # Layer 3:  Config file (most likely layer)
        if co.ini and self._cfg_file_cache:
            (section, key) = co.ini
            try:
                return self._cfg_file_cache[section][key]
            except KeyError:
                pass
        # Layer 4:  Default (set at the ConfigObject layer)
        if co.default is NotSet:
            raise AttributeError("Unable to find value for {}".format(attr))
        else:
            return co.default

    def items(self):
        for co in self.__options.values():
            try:
                value = self.get(co.name, NotSet)
                yield (co.name, value)
            except AttributeError:
                pass

    @classmethod
    def find_options(self, **search):
        search = list(search.items())
        for op in self.__options.values():
            keep = True
            for (find_attr, find_value) in search:
                value = getattr(op, find_attr)
                if find_value != value:
                    keep = False
                    break
            if keep:
                yield op

    def touch(self, name):
        """ Pull in the default value (or value from another layer) and add it to the list of
        entries to be written back to the conf file layer. """
        value = self.get(name)
        self._writeback_keys.add(name)

    def load_config(self):
        # Q:  Use any contextmanager here (with)?
        cp = ConfigParser()
        cp.read(self._ini_file)
        cache = dict()
        for section in cp.sections():
            cache[section] = dict(cp.items(section))
        self._cfg_file_cache = cache

    def save_config(self):
        if not self._writeback_keys:
            # Nothing to do
            return
        sys.stderr.write("Updating {} entries in config file {}\n".format(len(self._writeback_keys),
                                                                          self._ini_file))
        # Assumes no external changes since reading the .ini file
        cp = ConfigParser()
        cp.read(self._ini_file)
        while self._writeback_keys:
            name = self._writeback_keys.pop()
            value = self._cached_values[name]
            (section, key) = self.__options[name].ini
            # XXX:  Debug / logging
            sys.stderr.write("Setting {}:  [{}] {} = {}\n".format(name, section, key, value))
            if not cp.has_section(section):
                cp.add_section(section)
            cp.set(section, key, value)
        # XXX: Add some kind of safe replace and/or temp file functionality here...
        with open(self._ini_file, "w", encoding="utf-8") as fp:
            cp.write(fp)


ConfigManager.add_config(
    _ConfigOption("uuid",
                  env="SHINNECOCK_UUID",
                  ini=("agent", "uuid"),
                  help="Unique ID for this specific agent.",
                  cli="uuid"),
    _ConfigOption("agent_name",
                  env="SHINNECOCK_NAME",
                  prompt=True,
                  ini=("agent", "name")),
    # Eventually the org may tie to the HEC Token
    _ConfigOption("agent_org",
                  env="SHINNECOCK_ORG",
                  ini=("agent", "organization"),
                  prompt=True,
                  help="An optional dotted notation hierarchical name.  "
                       "Preferably a registered DNS domain."),
    _ConfigOption("agent_description",
                  ini=("agent", "description"),
                  prompt=True,
                  help="A free form description field."),
    _ConfigOption("endpoint_url",
                  env="SHINNECOCK_ENDPOINT_URL",
                  ini=("endpoint", "url"),
                  prompt=True,
                  cli="endpoint_url"),
    _ConfigOption("endpoint_token",
                  env="SHINNECOCK_ENDPOINT_TOKEN",
                  ini=("endpoint", "token"),
                  prompt=True,
                  cli="endpoint_token"),
)

'''
    _ConfigOption("endpoint_proxy",
                  env="SHINNECOCK_ENDPOINT_PROXY",
                  ini=("endpoint", "proxy")),
    _ConfigOption("wifi_blacklist",
                  env="SHINNECOCK_WIFI_BLACKLIST",
                  ini=("wifi", "blacklist")),
    _ConfigOption("report_errors",
                  env="SHINNECOCK_REPORT_ERRORS",
                  ini=("collection", "errors")),
    _ConfigOption("report_nic_drivers",
                  ini=("collection", "network_drivers")),
'''


def _register_by_conf_group(conf, section):
    from six.moves import input
    for co in conf.find_options(ini_section=section, prompt=True):
        default = conf.get(co.name)
        print("Variable:  {0.name}  {0.help}  (default: {1})".format(co, default))
        value = input("{.name}> ".format(co))
        if value:
            conf.set(co.name, value)

def register(conf, args):
    if not conf.get("uuid"):
        conf.uuid = generate_agent_uuid()
    if args.no_prompt:
        print("Automated registration.  Using values from CLI / envvars only")
        for (key, value) in conf.items():
            if value:
                print("Setting {} to {!r}".format(key, value))
                conf.touch(key)
    else:
        _register_by_conf_group(conf, "endpoint")
        _register_by_conf_group(conf, "agent")

    conf.save_config()

    sys.stderr.write("Attempting to contact the endpoint to send a test event.\n")
    output_to_hec(conf, {"action": "register"} , source="kintyre_speedtest:register")


# Note:  bootstrapping issue.  We can't use the ConfigManager because it hasn't been started yet
default_cfg = os.environ.get("SHINNECOCK_CONFIG", os.path.join("~", ".kintyre_speedtest.ini"))


def cli():
    from argparse import ArgumentParser

    parser = ArgumentParser(description="Kintyre speedtest agent")
    parser.add_argument("--version", "-V", action="version", version=JSON_FORMAT_VER)

    parser.add_argument("--config", "-c",
                        default=default_cfg,
                        help="Location of the config file.  Defaults to %(default)s")

    parser.add_argument("--no-prompt",
                        action="store_true",
                        help="Disable interactive prompting.")

    modsl = parser.add_mutually_exclusive_group()
    modsl.add_argument("--register",
                       dest="mode",
                       action="store_const",
                       const="register",
                       default="speedtest",
                       help="Enable registration mode.  No speedtest is run in this mode.")

    endpnt = parser.add_argument_group("Endpoint Settings")
    endpnt.add_argument("--url",
                        metavar="URL",
                        dest="endpoint_url",
                        help="URL of the Splunk HEC (HTTP Event Collector)")
    endpnt.add_argument("--token",
                        metavar="TOKEN",
                        dest="endpoint_token",
                        help="Authentication token for Splunk HEC.")

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

    parser.add_argument("--speedtest-debug", action="store_true",
                        help="Enable speedtest internal debugging features.  Very much noise.")

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
                        help="Disable speedtest functionality and return a bogus payload instead.  "
                             "ONLY useful for testing.")


    args = parser.parse_args()

    args.config = os.path.expandvars(os.path.expanduser(args.config))

    conf = ConfigManager(args.config, cli_args=args, env=os.environ)
    conf.load_config()

    if args.mode == "register":
        register(conf, args)
        return

    if args.fake_it:
        # Inject this stub function for testing purposes (save some bandwidth/time)
        def run_speedtest(ip=None):
            return { "action" : "FAKE_SPEEDTEST", ip: ip }
        globals()["run_speedtest"] = run_speedtest

    if args.speedtest_debug:
        speedtest.DEBUG = True

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

    if not conf.get("uuid") or not conf.get("endpoint_url") or not conf.get("endpoint_token"):
        sys.stderr.write("Missing endpoint configuration values in {}.  Run {} --register mode.\n"
                         .format(args.config, parser.prog))
        sys.exit(99)


    # Send a ping!
    if not output_to_hec(conf, {"action": "ping"}, source="kintyre_speedtest:ping"):
        sys.stderr.write("Unable to ping the HEC endpoint.  Don't waste time trying to run a speed-test.")
        return
    # Register the first parameter to output_to_hec(), so we don't have to pass "conf" to main()
    out = functools.partial(output_to_hec, conf)
    main(interfaces, out)


if __name__ == '__main__':
    cli()
