"""
Support for DD-WRT routers.

For more details about this platform, please refer to the documentation at
https://home-assistant.io/components/device_tracker.ddwrt/
"""
import logging
import re
import threading
from datetime import timedelta

import requests
import voluptuous as vol

import homeassistant.helpers.config_validation as cv
from homeassistant.components.device_tracker import (
    DOMAIN, PLATFORM_SCHEMA, DeviceScanner)
from homeassistant.const import CONF_HOST, CONF_HOSTS, CONF_PASSWORD, CONF_USERNAME
from homeassistant.util import Throttle

# Return cached results if last scan was less then this time ago.
MIN_TIME_BETWEEN_SCANS = timedelta(seconds=5)

CONF_PROTOCOL = 'protocol'
CONF_SSH_KEY = 'ssh_key'
HOST_GROUP = 'Single host or list of hosts'

_LOGGER = logging.getLogger(__name__)

REQUIREMENTS = ['pexpect=4.0.1']

_DDWRT_DATA_REGEX = re.compile(r'\{(\w+)::([^\}]*)\}')
_MAC_REGEX = re.compile(r'(([0-9A-Fa-f]{1,2}\:){5}[0-9A-Fa-f]{1,2})')

_DDWRT_LEASES_CMD = 'cat /tmp/dnsmasq.leases | awk \'{print $2","$4}\''
_DDWRT_WL_CMD = ('wl -i eth1 assoclist | awk \'{print $2}\' && '
                 'wl -i eth2 assoclist | awk \'{print $2}\' ;')

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
        host = config.get(CONF_HOST, '')
        hosts = config.get(CONF_HOSTS, [])
        if host:
            self.host = host
            self.aps = []
        elif hosts:
            self.host = hosts[0]
            self.aps = []
            if len(hosts) > 1:
                self.aps = hosts[1:]
        self.username = config[CONF_USERNAME]
        self.password = config.get(CONF_PASSWORD, '')
        self.protocol = config[CONF_PROTOCOL]
        self.ssh_key = config.get(CONF_SSH_KEY, '')

        if self.protocol == 'ssh':
            if self.ssh_key:
                self.ssh_secret = {'ssh_key': self.ssh_key}
            elif self.password:
                self.ssh_secret = {'password': self.password}
            else:
                _LOGGER.error('No password or private key specified')
                self.success_init = False
                return
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

    def ssh_connection(self, host, cmds):
        """Retrieve data from DD-WRT by ssh."""
        from pexpect import pxssh, exceptions

        ssh = pxssh.pxssh()
        try:
            ssh.login(host, self.username, **self.ssh_secret)
        except exceptions.EOF as err:
            _LOGGER.debug('Connection refused. Is SSH enabled?')
            _LOGGER.error('Connection refused. Is SSH enabled?')
            return None
        except pxssh.ExceptionPxssh as err:
            _LOGGER.debug('Unable to connect via SSH: %s', str(err))
            _LOGGER.error('Unable to connect via SSH: %s', str(err))
            return None

        try:
            output = []
            for cmd in cmds:
                ssh.sendline(cmd)
                ssh.prompt()
                output.append(ssh.before.split(b'\n')[1:-1])
            ssh.logout()
            return output

        except pxssh.ExceptionPxssh as exc:
            _LOGGER.debug('Unexpected response from router: %s', exc)
            _LOGGER.error('Unexpected response from router: %s', exc)
            return None

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
            if not self.hostname_cache:
                host_data = self.ssh_connection(self.host,
                                                [_DDWRT_LEASES_CMD,
                                                 _DDWRT_WL_CMD])
                if not host_data:
                    return None
                self.hostname_cache = {line.split(",")[0]: line.split(",")[1]
                                       for line in host_data[0]}
                active_clients = [mac.lower() for mac in host_data[1]]
            else:
                if not host_data:
                    return None
                host_data = self.ssh_connection(self.host, [_DDWRT_WL_CMD])
                active_clients = [mac.lower() for mac in host_data[0]]
            for access_point in self.aps:
                ap_data = self.ssh_connection(access_point, [_DDWRT_WL_CMD])
                active_clients.extends([mac.lower() for mac in ap_data[0]])

            return active_clients


def _parse_ddwrt_response(data_str):
    """Parse the DD-WRT data format."""
    return {
        key: val for key, val in _DDWRT_DATA_REGEX
        .findall(data_str)}


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
