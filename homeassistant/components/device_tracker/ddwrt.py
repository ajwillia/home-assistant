"""
Support for DD-WRT routers.

For more details about this platform, please refer to the documentation at
https://home-assistant.io/components/device_tracker.ddwrt/
"""
import logging
import re
import threading
from datetime import timedelta
import time
import requests
import voluptuous as vol

import homeassistant.helpers.config_validation as cv
from homeassistant.components.device_tracker import (
    DOMAIN, PLATFORM_SCHEMA, DeviceScanner)
from homeassistant.const import CONF_HOST, CONF_HOSTS, CONF_PASSWORD, \
    CONF_USERNAME
from homeassistant.util import Throttle

from pexpect import pxssh, exceptions

# Return cached results if last scan was less then this time ago.
MIN_TIME_BETWEEN_SCANS = timedelta(seconds=5)

CONF_PROTOCOL = 'protocol'
CONF_SSH_KEY = 'ssh_key'
HOST_GROUP = 'Single host or list of hosts'

_LOGGER = logging.getLogger(__name__)

REQUIREMENTS = ['pexpect==4.0.1']

_DDWRT_DATA_REGEX = re.compile(r'\{(\w+)::([^\}]*)\}')
_MAC_REGEX = re.compile(r'(([0-9A-Fa-f]{1,2}\:){5}[0-9A-Fa-f]{1,2})')

_DDWRT_LEASES_CMD = 'cat /tmp/dnsmasq.leases | awk \'{print $2","$4}\''
_DDWRT_WL_CMD = ('nvram show 2> /dev/null | grep \'wl._ifname\' | awk -F '
                 '\'=\' \'{cmd="wl -i " $2 " assoclist"; while(cmd | '
                 'getline var) print var}\' | awk \'{print $2}\'')
_DDWRT_IW_CMD = ('iw dev | grep Interface | awk \'{cmd="iw dev " $2 " station'
                 ' dump"; while(cmd | getline var) print var}\' | grep Station'
                 ' | awk \'{print $2}\'')

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Exclusive(CONF_HOST, HOST_GROUP): cv.string,
    vol.Exclusive(CONF_HOSTS, HOST_GROUP): cv.ensure_list,
    vol.Required(CONF_USERNAME): cv.string,
    vol.Optional(CONF_PASSWORD): cv.string,
    vol.Optional(CONF_PROTOCOL, default='http'):
        vol.In(['http', 'ssh']),
    vol.Optional(CONF_SSH_KEY): cv.isfile,
})


# pylint: disable=unused-argument
def get_scanner(hass, config):
    """Validate the configuration and return a DD-WRT scanner."""
    try:
        return DdWrtDeviceScanner(config[DOMAIN])
    except ConnectionError:
        return None


class DdWrtDeviceScanner(DeviceScanner):
    """This class queries a wireless router running DD-WRT firmware."""

    def __init__(self, config):
        """Initialize the scanner."""
        host = config.get(CONF_HOST, None)
        hosts = config.get(CONF_HOSTS, [])
        if host:
            self.host = host
            self.aps = []
        elif hosts:
            self.host = hosts.pop(0)
            self.aps = hosts

        self.username = config[CONF_USERNAME]
        self.password = config.get(CONF_PASSWORD, '')
        self.protocol = config[CONF_PROTOCOL]
        self.ssh_key = config.get(CONF_SSH_KEY, None)

        if self.protocol == 'ssh':
            if self.ssh_key:
                self.ssh_secret = {'ssh_key': self.ssh_key}
            elif self.password:
                self.ssh_secret = {'password': self.password}
            else:
                _LOGGER.error('No password or private key specified')
                self.success_init = False
                return

            self.ssh_cons = SSHConnections()
            self.host_ddwrt_cmd_lookup = {}
            # loop through the host and any APs adding to the ssh connection
            #  helper
            for host in self.aps + [self.host]:
                self._add_ssh_host_and_check_wl(host)

        else:
            if not self.password:
                _LOGGER.error('No password specified')
                self.success_init = False
                return

        self.lock = threading.Lock()

        self.last_results = {}
        self.hostname_cache = {}
        data = self.get_ddwrt_data()
        if data is None:
            raise ConnectionError('Cannot connect to DD-Wrt router')

    def _add_ssh_host_and_check_wl(self, host):
        try:
            self.ssh_cons.add_host(host, self.username,
                                   password=self.password,
                                   ssh_key=self.ssh_key)
        except exceptions.EOF as err:
            _LOGGER.error('%s Connection refused. Is SSH enabled?' %
                          host)
        except pxssh.ExceptionPxssh as err:
            _LOGGER.error('Unable to connect via SSH: %s', str(err))

        # is wl or iw supported?
        result = self.ssh_cons.send_and_parse(host, 'wl ver')
        if result[0].count('not found') > 0:
            self.host_ddwrt_cmd_lookup[host] = _DDWRT_IW_CMD
        else:
            self.host_ddwrt_cmd_lookup[host] = _DDWRT_WL_CMD

    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()

        return self.last_results

    def get_device_name(self, device):
        """Return the name of the given device or None if we don't know."""
        with self.lock:
            # If not initialised and not already scanned and not found.
            if device not in self.hostname_cache:
                self.get_ddwrt_data()

            return self.hostname_cache.get(device, False)

    @Throttle(MIN_TIME_BETWEEN_SCANS)
    def _update_info(self):
        """Ensure the information from the DD-WRT router is up to date.

        Return boolean if scanning successful.
        """
        with self.lock:
            _LOGGER.info('Checking wireless clients')

            self.last_results = []

            active_clients = self.get_ddwrt_data()

            if not active_clients:
                return False

            self.last_results.extend(active_clients)

            return True

    def http_connection(self, url):
        """Retrieve data from DD-WRT by http."""
        try:
            response = requests.get(
                url,
                auth=(self.username, self.password),
                timeout=4)
        except requests.exceptions.Timeout:
            _LOGGER.error('Connection to the router timed out')
            return
        if response.status_code == 200:
            _LOGGER.debug('Received {0}'.format(response.text))
            return _parse_ddwrt_response(response.text)
        elif response.status_code == 401:
            # Authentication error
            _LOGGER.error(
                'Failed to authenticate, '
                'please check your username and password')
            return
        else:
            _LOGGER.error('Invalid response from ddwrt: %s', response)

    def get_ddwrt_data(self):
        """Retrieve data from DD-WRT and return parsed result."""
        if self.protocol == 'http':
            if not self.hostname_cache:
                _LOGGER.debug('Getting hostnames')
                # get hostnames from dhcp leases
                url = 'http://{}/Status_Lan.live.asp'.format(self.host)
                data = self.http_connection(url)

                # no data received
                if data is None:
                    _LOGGER.debug('No hostname data received')
                    return None

                dhcp_leases = data.get('dhcp_leases', None)

                # parse and cache leases
                if dhcp_leases:
                    _LOGGER.debug('Parsing http leases')
                    self.hostname_cache = _parse_http_leases(dhcp_leases)

            _LOGGER.debug('Getting active clients')
            # get active wireless clients
            url = 'http://{}/Status_Wireless.live.asp'.format(self.host)
            data = self.http_connection(url)

            if data is None:
                _LOGGER.debug('No active clients received')
                return None

            _LOGGER.debug('Parsing http clients')
            return _parse_http_wireless(data.get('active_wireless', None))

        elif self.protocol == 'ssh':
            active_clients = []

            # make sure the ssh connection helper has the host
            if self.ssh_cons.has_host(self.host):
                cmds = (_DDWRT_LEASES_CMD,
                        self.host_ddwrt_cmd_lookup[self.host])
                leases, clients = self.ssh_cons.issue_cmds(self.host, cmds)

                # convert leases into dict splitting on first comma
                host_data = dict(map(lambda l: l.split(',', 1), leases))

                # update hostname_cache
                self.hostname_cache.update(host_data)
                active_clients.extend(clients)
            else:
                # it doesn't so try and add.  will wait until next
                # event loop to get the data
                self._add_ssh_host_and_check_wl(self.host)

            for ap in self.aps:
                if self.ssh_cons.has_host(ap):
                    cmd = self.host_ddwrt_cmd_lookup[ap]
                    clients = self.ssh_cons.send_and_parse(ap, cmd)
                    active_clients.extend(clients)
                else:
                    self._add_ssh_host_and_check_wl(ap)
            return active_clients


def _parse_ddwrt_response(data_str):
    """Parse the DD-WRT data format."""
    return {key: val for key, val in _DDWRT_DATA_REGEX.findall(data_str)}


def _parse_http_leases(dhcp_leases):
    """Parse lease data returned by web."""
    # Remove leading and trailing quotes and spaces
    cleaned_str = dhcp_leases.replace(
        "\"", "").replace("\'", "").replace(" ", "")
    elements = cleaned_str.split(',')
    num_clients = int(len(elements) / 5)
    hostname_cache = {}
    for idx in range(0, num_clients):
        # The data is a single array
        # every 5 elements represents one host, the MAC
        # is the third element and the name is the first.
        mac_index = (idx * 5) + 2
        if mac_index < len(elements):
            mac = elements[mac_index]
            hostname_cache[mac] = elements[idx * 5]

    return hostname_cache


def _parse_http_wireless(active_wireless):
    """Parse wireless data returned by web."""
    if not active_wireless:
        return False

    # The DD-WRT UI uses its own data format and then
    # regex's out values so this is done here too
    # Remove leading and trailing single quotes.
    clean_str = active_wireless.strip().strip("'")
    elements = clean_str.split("','")

    return [item for item in elements if _MAC_REGEX.match(item)]


class SSHConnection(object):
    """
        manages an SSH connection to a host
    """

    def __init__(self, host, username, password='',
                 ssh_key=None, timeout=5):
        self.host = host
        self.username = username
        self.password = password
        self.ssh_key = ssh_key
        self.timeout = timeout
        self._connect()

    @property
    def is_alive(self):
        """ issue some kind of command to see if the connection is alive """
        self.ssh.sendline("clear")
        return self.ssh.prompt()

    def _connect(self):
        self.ssh = pxssh.pxssh(timeout=self.timeout)
        self.ssh.login(self.host, self.username, password=self.password,
                       ssh_key=self.ssh_key)

    def send_and_parse(self, cmd):
        """ helper method which sends the cmd, parses and returns the
        results """
        if not self.is_alive:
            # try reconnecting once if the connection is not alive
            self._connect()

        self.ssh.sendline(cmd)
        self.ssh.prompt()
        results = []
        data = self.ssh.before.decode('ascii').split('\r\n')
        for item in data[:-1]:
            if cmd.count(item.strip()) == 0:
                results.append(item)
        return results

    def issue_cmds(self, cmds):
        """ helper method to issue a series of commands,
            parse each result and return results as a list"""
        output = []
        for cmd in cmds:
            output.append(self.send_and_parse(cmd))
        return output


class SSHConnections(object):
    """
        collection of SSHConnection
    """

    def __init__(self):
        self.hosts = {}

    def add_host(self, host, username, password='', ssh_key=None):
        ssh = SSHConnection(host, username, password=password,
                            ssh_key=ssh_key)
        self.hosts[host] = ssh

    def has_host(self, host):
        return host in self.hosts.keys()

    def is_alive(self, host):
        return self.hosts[host].is_alive

    def send_and_parse(self, host, cmd):
        return self.hosts[host].send_and_parse(cmd)

    def issue_cmds(self, host, cmds):
        return self.hosts[host].issue_cmds(cmds)

    def send_and_parse(self, host, cmd):
        return self.hosts[host].send_and_parse(cmd)

