#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)

__author__ = "Paul Greenberg @greenpau"
__version__ = "1.0"
__maintainer__ = "Paul Greenberg"
__email__ = "greenpau@outlook.com"
__status__ = "Alpha"

import os
import sys
import argparse
import traceback;
import yaml;
import json
import logging;
import mimetypes;
import re;
import time;
import pickle;
import ipaddress;
from datetime import datetime;
import pprint;
import socket
import struct

class ToolkitError:
    def __init__(self, err):
        if isinstance(err, str):
            self.error_message = "%s" % err;
            return
        self.error_type = "%s" % str(err[0]);
        self.error_message = "%s" % err[1];
        if len(err) < 3:
            return
        if err[2] is None:
            return
        self.error_details = []
        for traceback_line in traceback.format_tb(err[2]):
            self.error_details.append("%s" % (traceback_line))
        return

    def __repr__(self):
        err = self.error_message
        if hasattr(self, "error_type"):
            err = "%s: %s" % (self.error_type, err);
        if hasattr(self, "error_details"):
            err += "\n%s" %  ('\n'.join(self.error_details));
        return err

class ToolkitDatabase(object):
    def __init__(self, data_dir=None, use_cache=False, host_filter=None):
        self.log = logging.getLogger(self.__class__.__name__);
        self.data_dir = None;
        self.host_filter = host_filter;
        if not data_dir:
            #raise Exception("init", "no data directory specified");
            return
        if not self._is_dir_exists(data_dir):
            raise Exception("init", "data directory does not exist: %s" % (data_dir));
        if self._is_dir_empty(data_dir):
            raise Exception("init", "data directory is empty: %s" % (data_dir));
        self.data_dir = data_dir;
        self.log.info("data directory: %s" % (data_dir));
        if use_cache:
            self.cache_dir = os.path.join(self.data_dir, '.ndmtk');
            self.cache_file = os.path.join(self.cache_dir, 'cache');
            self.log.info("cache file: %s" % (self.cache_file));
            if self._is_cache_exists():
                self._load_cache();
        else:
            self._construct_inventory();
        if use_cache:
            self._save_cache();
        return;

    def _load_cache(self):
        epoch = time.time();
        try:
            with open(self.cache_file, 'rb') as f:
                self.data = pickle.load(f);
        except:
            err = ToolkitError(sys.exc_info());
            self.log.error(err);
            return;
        self.log.info("restored cached data at '" + str(datetime.now()) + "', took " + str(time.time() - epoch) + "s");


    def _save_cache(self):
        epoch = time.time();
        if not self._is_dir_exists(self.cache_dir):
            try:
                os.mkdir(self.cache_dir);
            except:
                err = ToolkitError(sys.exc_info());
                self.log.error(err);
                return;
        with open(self.cache_file, 'wb') as f:
            pickle.dump(self.data, f, pickle.HIGHEST_PROTOCOL);
        self.log.info("saved data to cache at '" + str(datetime.now()) + "', took " + str(time.time() - epoch) + "s");


    def _is_cache_exists(self):
        if not self._is_file_exists(self.cache_file):
            return False;
        return True;


    @staticmethod
    def _is_file_exists(fn):
        if not os.path.exists(fn):
            ''' path does not exist '''
            return False;
        if not os.path.isfile(fn):
            ''' not a file '''
            return False;
        if not os.access(fn, os.R_OK):
            ''' not readable '''
            return False;
        return True;

    @staticmethod
    def _is_dir_empty(fn):
        for dirpath, dirnames, files in os.walk(os.path.expanduser(fn)):
            if len(files) > 0 or len(dirnames) > 0:
                return False;
        return True;

    @staticmethod
    def _is_dir_exists(fn):
        if not os.path.exists(fn):
            ''' path does not exist '''
            return False;
        if not os.path.isdir(fn):
            ''' not a directory '''
            return False;
        if not os.access(fn, os.R_OK):
            ''' not readable '''
            return False;
        return True;


    @staticmethod
    def _is_file_empty(fn):
        try:
            fn_info = os.stat(fn);
            if fn_info.st_size == 0:
                return True
        except:
            pass;
        return False;

    @staticmethod
    def _has_required_field(fields, d):
        if len(d) == 0:
            return False;
        for f in fields:
            if f not in d:
                return False
        return True

    def _construct_inventory(self):
        '''
        Browse the files in the input directory directory, identify relevant
        meta, and construct file tree.
        '''
        self.data = {};
        try:
            for dirName, subDirList, fileList in os.walk(self.data_dir):
                for fileName in fileList:
                    origFilePath = os.path.join(dirName, fileName);
                    filePath = re.sub(self.data_dir, '', origFilePath);
                    fileName = os.path.basename(filePath);
                    fileDir = re.sub(fileName, '', origFilePath)
                    if not fileName.endswith('meta.yml'):
                        continue;
                    if self.host_filter:
                        if not fileName.startswith(self.host_filter):
                            continue
                    fc = None;
                    with open(origFilePath, "r") as f:
                        try:
                            fc = yaml.load(f);
                        except:
                            err = ToolkitError(sys.exc_info());
                            self.log.error(err);
                            continue
                    fields = ['conf', 'cli'];
                    if not self._has_required_field(fields, fc):
                        continue
                    fields = ['host', 'os'];
                    if not self._has_required_field(fields, fc['conf']):
                        continue;
                    h = fc['conf']['host'];
                    for i, c in enumerate(fc['cli']):
                        fields = ['cli', 'status', 'path', 'lines'];
                        if not self._has_required_field(fields, c):
                            continue
                        if c['status'] != 'ok':
                            continue;
                        cc = {
                            'seq': i,
                            'input': c['cli'],
                            'file': os.path.basename(c['path']),
                            'lines': int(c['lines']),
                        };
                        try:
                            f = self.data[h];
                        except:
                            self.data[h] = {
                                'data_dir': fileDir,
                                'conf': fc['conf'],
                            };
                            if 'facts' in fc['status']:
                                self.data[h]['facts'] = fc['status']['facts']
                        try:
                            f = self.data[h]['cli'];
                        except:
                            self.data[h]['cli'] = [];
                        self.data[h]['cli'].append(cc)
                    self.log.info("host: %s" % (fc['conf']['host']));
        except:
            err = ToolkitError(sys.exc_info());
            self.log.error(err);
        return

    @staticmethod
    def get_relevant_file(file_type=None, operating_system=None, files=[]):
        if not file_type:
            return
        cliMap = {
            'interfaces': {
                'junos_qfx': [
                    'show interfaces statistics',
                ],
                'junos_mx': [
                    'show interfaces statistics',
                ],
                'cisco_asa': [
                    'show interface',
                ],
                'paloalto_panos': [
                    'show interface all',
                ],
            },
            'arp_entries': {
                'junos_qfx': [
                    'show arp no-resolve',
                ],
                'junos_mx': [
                    'show arp no-resolve',
                ],
                'cisco_asa': [
                    'show arp',
                ],
                'paloalto_panos': [
                    'show arp all',
                    'show arp all dns no',
                ],
            },
            'syslog_servers': {
                'junos_qfx': [
                    'show configuration | display set',
                ],
                'junos_mx': [
                    'show configuration | display set',
                ],
            },
            'snmp_servers': {
                'junos_qfx': [
                    'show configuration | display set',
                ],
                'junos_mx': [
                    'show configuration | display set',
                ],
            },
            'ntp_servers': {
                'junos_qfx': [
                    'show ntp associations',
                ],
                'junos_mx': [
                    'show ntp associations',
                ],
            },
            'aaa_servers': {
                'junos_qfx': [
                    'show configuration | display set',
                ],
                'junos_mx': [
                    'show configuration | display set',
                ],
            },
            'local_users': {
                'junos_qfx': [
                    'show configuration | display set',
                ],
                'junos_mx': [
                    'show configuration | display set',
                ],
            },
            'lldp_neighbors': {
                'junos_qfx': [
                    'show lldp neighbors',
                ],
                'junos_mx': [
                    'show lldp neighbors',
                ],
            },
            'ospf_neighbors': {
                'junos_qfx': [
                    'show ospf neighbor detail',
                ],
                'junos_mx': [
                    'show ospf neighbor detail',
                ],
            },
        }
        if file_type not in cliMap:
            return
        if operating_system not in cliMap[file_type]:
            return
        for f in files:
            if f['input'] in cliMap[file_type][operating_system]:
                return f['file']
        return None

    @staticmethod
    def get_file_contents(fp, patterns=None):
        data = []
        lines = None
        try:
            with open(fp, "r") as f:
                lines = f.readlines()
        except:
            with open(fp.lower(), "r") as f:
                lines = f.readlines()
        if not patterns:
            return [x.rstrip() for x in lines]
        for line in lines:
            for pattern in patterns:
                if re.match(pattern, line):
                    line = line.rstrip()
                    data.append(line)
                    break
        return data

    def get_ip_interfaces_paloalto_panos(self,fp):
        interfaces = []
        self.log.info("get_ip_interfaces_paloalto_panos(): %s" % (fp))
        lines = self.get_file_contents(fp)
        mac_address_ptrn = '(?P<mac_address>[a-f0-9]{1,2}:[a-f0-9]{1,2}:[a-f0-9]{1,2}:\S+)'
        interface_ptrn = '(?P<name>\S+)\s+(?P<id>\d+)'
        vsys_ptrn = '(?P<vsys>\d+)\s+(?P<zone>\S+)\s+(?P<fwd>\S+)'
        vlan_ptrn = '(?P<vlan>\d+)'
        ipaddress_ptrn = '(?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{2})'
        physical_interfaces = {}
        for line in lines:
            match_mac_address = re.match(interface_ptrn + '\s+(?P<interface_state>\S+)\s+' +  mac_address_ptrn, line)
            if match_mac_address:
                interface_name = match_mac_address.groupdict()['name']
                interface_mac_address = match_mac_address.groupdict()['mac_address']
                interface_state = match_mac_address.groupdict()['interface_state']
                if interface_name not in physical_interfaces:
                    physical_interfaces[interface_name] = {
                        'mac_address': interface_mac_address,
                        'state': interface_state,
                    }
                continue
            match_ip_address = re.match(interface_ptrn + '\s+' + vsys_ptrn + '\s+' + vlan_ptrn + '\s+' + ipaddress_ptrn, line)
            if match_ip_address:
                interface_name = match_ip_address.groupdict()['name']
                interface_mac_address = None
                if len(interface_name.split('.')) == 2:
                    parent_interface = interface_name.split('.')[0]
                    if parent_interface in physical_interfaces:
                        interface_mac_address = physical_interfaces[parent_interface]['mac_address']
                else:
                    if interface_name in physical_interfaces:
                        interface_mac_address = physical_interfaces[interface_name]['mac_address']
                interface_vlan = match_ip_address.groupdict()['vlan']
                interface_zone = match_ip_address.groupdict()['zone']
                interface_vsys = match_ip_address.groupdict()['vsys']
                interface_fwd = match_ip_address.groupdict()['fwd']
                interface_description = 'vsys: ' + interface_vsys
                interface_description += ', zone: ' + interface_zone
                interface_description += ', fwd: ' + interface_fwd
                interface_type = 'logical'
                if interface_vlan:
                    if interface_vlan in ['', '0']:
                        interface_type = 'physical'
                        interface_vlan = None
                interface_vlan = self._normalize_vlan(interface_vlan)
                interface_ip_address = match_ip_address.groupdict()['ip_address']
                if interface_ip_address.startswith('128.'):
                    continue
                if interface_ip_address.startswith('127.'):
                    continue
                if interface_ip_address.startswith('1.'):
                    continue
                interface = {
                    'name': interface_name,
                    'type': interface_type,
                    'ip_address': interface_ip_address,
                    #'state': interface_state,
                }
                data = self.get_ip_network(interface_ip_address)
                if data:
                    interface['ip_address'] = data['ip_address']
                    interface['ip_network'] = data['ip_network']
                    interface['prefix_len'] = int(data['prefix_len'])
                if interface_mac_address:
                    interface['mac_address'] = self._normalize_mac_address(interface_mac_address)
                if interface_vlan:
                    interface['vlan'] = interface_vlan
                if interface_description:
                    interface['description'] = interface_description
                interfaces.append(interface)
                continue
            self.log.info("unmatched line: %s" % (line))
        return interfaces

    @staticmethod
    def rekey(k):
        k = k.strip().replace(' ', '_').replace('-', '_').lower()
        return k

    @staticmethod
    def revalue(k, v):
        intFields = [
            'input_errors', 'input_packets', 'interface_index',
            'snmp_ifindex', 'output_errors', 'output_packets',
            'mtu'
        ]
        v = v.strip()
        if k in intFields:
            if re.match('^\d+$', v):
                v = int(v)
        return v

    def get_interface_props_junos_qfx(self,fp):
        return self.get_interface_props_junos(fp)

    def get_interface_props_junos(self,fp):
        interfaces = []
        self.log.info("get_interface_props_junos(): %s" % (fp))
        lines = self.get_file_contents(fp, None)
        interface = None
        for line in lines:
            if re.match('^\s*$', line):
                continue
            if re.match('{master', line):
                continue
            match_physical_interface = re.match('Physical interface:\s+(?P<interface_name>\S+),', line)
            if match_physical_interface:
                if interface:
                    interfaces.append(interface)
                interface = {
                    'interface_name': match_physical_interface.groupdict()['interface_name']
                }
                interface['type'] = 'physical'
                continue
            match_logical_interface = re.match('\s+Logical interface\s+(?P<interface_name>\S+)\s', line)
            if match_logical_interface:
                if interface:
                    interfaces.append(interface)
                interface = {
                    'interface_name': match_logical_interface.groupdict()['interface_name']
                }
                interface['type'] = 'logical'
                continue
            if re.match('\s+Description: ', line):
                interface['description'] = line.strip().replace('Description: ', '')
                continue
            match_mac_address = re.match('\s+Current address:\s+(?P<mac_address>\S+), Hardware address: (?P<hw_mac_address>\S+)', line)
            if match_mac_address:
                interface['mac_address'] =  match_mac_address.groupdict()['mac_address']
                interface['hw_mac_address'] = match_mac_address.groupdict()['hw_mac_address']
                continue
            if re.match('\s+(Last flapped|Statistics last cleared|PCS statistics)', line):
                continue
            if re.match('\s+Statistics\s+Packets\s+pps\s+Bytes\s+bps', line):
                continue
            if line.strip() == 'Addresses':
                continue
            match_cos_queue = re.match('\s+CoS queues\s*:\s*(?P<supported>\d+) supported, (?P<max_usable>\d+) maximum usable queues', line)
            if match_cos_queue:
                interface['cos_queue_supported'] = match_cos_queue.groupdict()['supported']
                interface['cos_queue_max_usable'] = match_cos_queue.groupdict()['max_usable']
                continue
            # various shims
            if ' Encapsulation: ' in line:
                line = line.replace(' Encapsulation: ', ', Encapsulation: ')
            if '  Protocol ' in line:
                line = line.replace('  Protocol ', '  Protocol: ')
            if ' Internal: 0x' in line:
                line = line.replace(' Internal: 0x', ' , Internal Flag: 0x')
            if '  Addresses, Flags: ' in line:
                line = line.replace('  Addresses, Flags: ', 'Address Flags: ')
            if ' Bridging Domain: ' in line:
                line = line.replace(' Bridging Domain: ', ', Bridging Domain: ')
            if 'Bit errors ' in line:
                line = line.replace('Bit errors ', 'Bit errors: ')
            if 'Errored blocks' in line:
                line = line.replace('Errored blocks ', 'Errored blocks: ')
            # parse through key-value pairs
            _kv_found = True
            for pairs in line.split(','):
                pairs = pairs.strip().split(':')
                if len(pairs) == 2:
                    k = self.rekey(pairs[0])
                    v = self.revalue(k, pairs[1])
                    interface[k] = v
                else:
                    match_phy_mode = re.match('(?P<phy_mode>LAN|WAN)-PHY mode', pairs[0])
                    if match_phy_mode:
                        interface['phy_mode'] = match_phy_mode.groupdict()['phy_mode']
                        continue
                    _kv_found = False
            if _kv_found:
                continue
            if re.match('\s+Flags: ', line):
                interface['flags'] = line.strip().replace('Flags: ', '')
                continue
            match_ipv6_addr = re.match('\s+Destination: (?P<ipv6_network>\S+), Local: (?P<ipv6_address>\S+)', line)
            if match_ipv6_addr:
                interface['ipv6_network'] = match_ipv6_addr.groupdict()['ipv6_network']
                interface['ipv6_address'] = match_ipv6_addr.groupdict()['ipv6_address']
                continue
            if 'Down ' in line:
                ''' This is a snowflake. Get encapsulation only. '''
                match_encaps = re.match('.*Encapsulation: (?P<encapsulation>\S+)', line)
                if match_encaps:
                    interface['encapsulation'] = match_encaps.groupdict()['encapsulation']
                    continue
            self.log.info("unmatched line: %s" % (line))
        if interface:
            interfaces.append(interface)
        #self.log.info(pprint.pformat(interfaces))
        return interfaces

    def get_ntp_servers_junos_qfx(self,fp):
        return self.get_ntp_servers_junos(fp)

    def get_ntp_servers_junos(self,fp):
        servers = []
        self.log.info("get_ntp_servers_junos(): %s" % (fp))
        headers = ['ntp_server', 'refid', 'st', 't', 'when', 'poll', 'reach', 'delay', 'offset', 'jitter']
        lines = self.get_file_contents(fp, None)
        server = {}
        for line in lines:
            line = line.strip()
            if line.startswith('{master') or line.startswith('===') or line.startswith('remote') or line == '':
                continue
            item = [x for x in line.split(' ') if x]
            if len(item) == 10:
                server = {}
                for i, h in enumerate(headers):
                    server[h] = item[i]
                server['flags'] = []
                if 'ntp_server' in server:
                    if '*' in server['ntp_server']:
                        server['flags'].append('master synched')
                    if '#' in server['ntp_server']:
                        server['flags'].append('master unsynced')
                    if '+' in server['ntp_server']:
                        server['flags'].append('selected')
                    if '-' in server['ntp_server']:
                        server['flags'].append('candidate')
                    if '~' in server['ntp_server']:
                        server['flags'].append('configured')
                    server['ntp_server'] = server['ntp_server'].replace('*', '').replace('#', '').replace('+', '').replace('-', '').replace('~', '')
                servers.append(server)
                continue
            self.log.info("unmatched line: %s" % (line))
        return servers

    def get_lldp_neighbors_junos_qfx(self,fp):
        return self.get_lldp_neighbors_junos(fp)

    def get_lldp_neighbors_junos(self,fp):
        neighbors = []
        self.log.info("get_lldp_neighbors_junos(): %s" % (fp))
        lines = self.get_file_contents(fp, None)
        column_map = None
        for line in lines:
            if line.startswith('{master') or line.strip() == '':
                continue
            if line.startswith('Local Interface'):
                column_map = self.get_column_map(line)
                continue
            if column_map:
                column_data = self.get_column_data(column_map, line)
                if column_data:
                    entry = {}
                    for k in column_data:
                        if k == 'parent_interface':
                            entry['local_parent_interface'] = column_data[k]
                        elif k == 'port_info':
                            entry['neighbor_interface'] = column_data[k]
                        elif k == 'chassis_id':
                            entry['neighbor'] = column_data[k]
                        else:
                            entry[k] = column_data[k]
                    neighbors.append(entry)
                    continue
            self.log.info("unmatched line: %s" % (line))
        return neighbors

    def get_ospf_neighbors_junos_qfx(self,fp):
        return self.get_ospf_neighbors_junos(fp)

    def get_ospf_neighbors_junos(self,fp):
        neighbors = []
        self.log.info("get_ospf_neighbors_junos(): %s" % (fp))
        lines = self.get_file_contents(fp, None)
        column_map = None
        p = 0
        for line in lines:
            if line.startswith('{master') or line.strip() == '':
                continue
            if not column_map and line.startswith('Address'):
                column_map = self.get_column_map(line)
                continue
            if column_map and not line.startswith(' '):
                column_data = self.get_column_data(column_map, line)
                if column_data:
                    entry = {}
                    for k in column_data:
                        if k == 'id':
                            entry['router_id'] = column_data[k]
                        else:
                            entry[k] = column_data[k]
                    neighbors.append(entry)
                    p += 1
                    continue
            else:
                if p > 0:
                    i = p - 1
                    parts = line.split(',')
                    for part in parts:
                        part = part.strip()
                        s = ' '
                        if part.count(':') == 1:
                            s = ':'
                        j = part.index(s)
                        k = part[:j].strip().lower().replace(' ', '_')
                        v = part[j:].strip()
                        if part.count(':') == 1:
                            v = part[j+1:].strip()
                        neighbors[i][k] = v
                    continue
            self.log.info("unmatched line: %s" % (line))
        return neighbors

    def get_aaa_servers_junos_qfx(self,fp):
        return self.get_aaa_servers_junos(fp)

    def get_aaa_servers_junos(self,fp):
        servers = {}
        self.log.info("get_aaa_servers_junos(): %s" % (fp))
        patterns = [
            'set system tacplus-server'
        ]
        lines = self.get_file_contents(fp, patterns)
        for line in lines:
            if line.startswith('set system tacplus-server'):
                line = line.replace('set system tacplus-server', '').strip()
                parts = line.split(' ')
                server = parts.pop(0)
                if server not in servers:
                    servers[server] = {'server': server}
                attr = parts.pop(0)
                if attr in ['port', 'secret', 'source-address']:
                    servers[server][attr] = ' '.join(parts).strip()
                    if attr == 'secret':
                        servers[server][attr] = servers[server][attr].strip('"')
                else:
                    self.log.info("unmatched line: %s" % (line))
                continue
            self.log.info("unmatched line: %s" % (line))
        server_list = []
        for server in sorted(servers):
            server_list.append(servers[server])
        return server_list

    def get_local_users_junos_qfx(self,fp):
        return self.get_local_users_junos(fp)

    def get_local_users_junos(self,fp):
        users = {}
        self.log.info("get_local_users_junos(): %s" % (fp))
        patterns = [
            'set system login user'
        ]
        lines = self.get_file_contents(fp, patterns)
        for line in lines:
            if line.startswith('set system login user'):
                line = line.replace('set system login user', '').strip()
                parts = line.split(' ')
                username = parts.pop(0)
                if username not in users:
                    users[username] = {'username': username}
                attr = parts.pop(0)
                if attr in ['uid', 'full-name', 'class', 'authentication']:
                    users[username][attr] = ' '.join(parts).strip()
                continue
            self.log.info("unmatched line: %s" % (line))
        user_list = []
        for user in sorted(users):
            user_list.append(users[user])
        return user_list

    def get_snmp_servers_junos_qfx(self,fp):
        return self.get_snmp_servers_junos(fp)

    def get_snmp_servers_junos(self,fp):
        servers = []
        self.log.info("get_snmp_servers_junos(): %s" % (fp))
        patterns = [
            'set snmp'
        ]
        lines = self.get_file_contents(fp, patterns)
        server = {}
        for line in lines:
            _continue = False
            for k in ['contact', 'description', 'location']:
                if line.startswith('set snmp ' + k):
                    line = line.replace('set snmp ' + k, '').strip().strip('"')
                    server[k] = line
                    _continue = True
                    break
            if _continue:
                continue
            if line.startswith('set snmp community'):
                line = line.replace('set snmp community', '').strip()
                parts = line.split();
                community = parts.pop(0)
                scope = parts.pop(0)
                if 'communities' not in server:
                    server['communities'] = {}
                if community not in server['communities']:
                    server['communities'][community] = {}
                if scope not in server['communities'][community]:
                    server['communities'][community][scope] = []
                server['communities'][community][scope].extend(parts)
                continue
            if line.startswith('set snmp trap-options source-address'):
                server['trap_source_address'] = line.split(' ')[-1:][0]
                continue
            if line.startswith('set snmp trap-group'):
                line = line.replace('set snmp trap-group', '').strip()
                parts = line.split();
                group = parts.pop(0)
                scope = parts.pop(0)
                if 'trap_groups' not in server:
                    server['trap_groups'] = {}
                if group not in server['trap_groups']:
                    server['trap_groups'][group] = {}
                if scope not in server['trap_groups'][group]:
                    server['trap_groups'][group][scope] = []
                server['trap_groups'][group][scope].extend(parts)
                continue
            if line.startswith('set snmp traceoptions'):
                continue
            if line.startswith('set snmp view'):
                continue
            if line.startswith('set snmp health'):
                continue
            self.log.info("unmatched line: %s" % (line))
        servers.append(server)
        return servers

    def get_syslog_servers_junos_qfx(self,fp):
        return self.get_syslog_servers_junos(fp)

    def get_syslog_servers_junos(self,fp):
        servers = {}
        self.log.info("get_syslog_servers_junos(): %s" % (fp))
        patterns = [
            'set system syslog host'
        ]
        lines = self.get_file_contents(fp, patterns)
        for line in lines:
            if re.match('set system syslog (user|file)', line):
                continue
            match_host = re.match('set system syslog host (?P<server>\S+)\s(?P<props>.*)', line)
            if match_host:
                server = match_host.groupdict()['server']
                props = match_host.groupdict()['props']
                if server not in servers:
                    servers[server] = {'destination': server, 'properties': []}
                servers[server]['properties'].append(props)
                continue
            self.log.info("unmatched line: %s" % (line))
        output = []
        for server in servers:
            output.append(servers[server])
        return output

    def get_ip_interfaces_junos_qfx(self,fp):
        return self.get_ip_interfaces_junos(fp)

    def get_ip_interfaces_junos(self,fp):
        interfaces = []
        self.log.info("get_ip_interfaces_junos(): %s" % (fp))
        patterns = [
            '\s*Physical interface',
            '\s+Logical interface',
            '\s+Current address:',
            '\s+Destination:',
        ]
        lines = self.get_file_contents(fp, patterns)
        interface_name = None
        interface_type = None
        interface_mac_address = None
        interface_ip_address = None
        interface_state = 'unknown'
        for line in lines:
            match_physical_interface = re.match('Physical interface:\s+(?P<interface_name>\S+),', line)
            if match_physical_interface:
                interface_type = 'physical'
                interface_name = match_physical_interface.groupdict()['interface_name']
                interface_mac_address = None
                interface_ip_address = None
                if re.search('link is [Uu]p', line):
                    interface_state = 'up'
                elif re.search('link is [Dd]own', line):
                    interface_state = 'down'
                else:
                    interface_state = 'unknown'
                continue
            match_logical_interface = re.match('\s+Logical interface\s+(?P<interface_name>\S+)\s', line)
            if match_logical_interface:
                interface_type = 'logical'
                interface_name = match_logical_interface.groupdict()['interface_name']
                interface_ip_address = None
                continue
            match_mac_address = re.match('\s+Current address:\s+(?P<interface_mac_address>\S+),', line)
            if match_mac_address:
                interface_mac_address =  match_mac_address.groupdict()['interface_mac_address']
                continue
            ip_prefix_pattern = '\s+Destination:\s+(?P<ip_prefix>\S+)/(?P<ip_prefix_len>\d{1,3}),'
            ip_address_pattern = 'Local:\s+(?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),'
            match_ip_address = re.match(ip_prefix_pattern + ' ' + ip_address_pattern, line)
            if match_ip_address:
                interface_ip_prefix_len = match_ip_address.groupdict()['ip_prefix_len']
                interface_ip_address = match_ip_address.groupdict()['ip_address'] + '/' + interface_ip_prefix_len
                if interface_ip_address.startswith('128.') or interface_ip_address.startswith('127.'):
                    continue
                if interface_name.endswith('.0'):
                    interface_name = interface_name[:-2]
                    interface_type = 'physical'
                interface = {
                    'name': interface_name,
                    'type': interface_type,
                    'ip_address': interface_ip_address,
                    'state': interface_state,
                }
                match_vlan = re.match('.*\.(?P<interface_vlan>\d+)$', interface_name)
                if match_vlan:
                    interface_vlan = match_vlan.groupdict()['interface_vlan']
                    interface['vlan'] = self._normalize_vlan(interface_vlan)
                data = self.get_ip_network(interface_ip_address)
                if data:
                    interface['ip_address'] = data['ip_address']
                    interface['ip_network'] = data['ip_network']
                    interface['prefix_len'] = int(data['prefix_len'])
                if interface_mac_address:
                    interface['mac_address'] = self._normalize_mac_address(interface_mac_address)
                interfaces.append(interface)
                continue
            self.log.info("unmatched line: %s" % (line))
        return interfaces

    def get_ip_interfaces_cisco_asa(self, fp):
        interfaces = []
        self.log.info("get_ip_interfaces_cisco_asa(): %s" % (fp))
        patterns = [
            '^Interface',
            '^\s+VLAN identifier',
            '^\s+Description:',
            '^\s+MAC address',
            '^\s+IP address',
        ]
        lines = self.get_file_contents(fp, patterns)
        interface_name = None
        interface_alias = None
        interface_mac_address = None
        interface_ip_address = None
        interface_mtu = None
        interface_vlan = None
        interface_description = None
        interface_state = 'unknown'
        for line in lines:
            if re.search('IP address unassigned', line):
                continue
            interface_name_pattern = '^Interface\s+(?P<interface_name>\S+) "(?P<interface_alias>\S*)"'
            interface_state_pattern = 'is (?P<interface_state>\S+\s*\S*), line protocol is (?P<interface_proto_state>\S+\s*\S*)'
            match_interface = re.match(interface_name_pattern + ', ' + interface_state_pattern, line)
            if match_interface:
                interface_name = match_interface.groupdict()['interface_name']
                interface_alias = match_interface.groupdict()['interface_alias']
                interface_mac_address = None
                interface_ip_address = None
                interface_mtu = None
                interface_description = None
                interface_vlan = None
                interface_state = match_interface.groupdict()['interface_state']
                interface_proto_state = match_interface.groupdict()['interface_proto_state']
                if interface_proto_state != 'up':
                    interface_state = 'down'
                continue
            match_mac_address = re.match('\s+MAC address\s+(?P<interface_mac_address>\S+), MTU (?P<interface_mtu>\S+)', line)
            if match_mac_address:
                interface_mac_address =  match_mac_address.groupdict()['interface_mac_address']
                interface_mtu = match_mac_address.groupdict()['interface_mtu']
                interface_mtu = self._normalize_mtu(interface_mtu)
                continue
            match_description = re.match('\s+Description: (?P<interface_description>.*)', line)
            if match_description:
                interface_description = match_description.groupdict()['interface_description']
                continue
            match_vlan = re.match('\s+VLAN identifier (?P<interface_vlan>\d+)', line)
            if match_vlan:
                interface_vlan = match_vlan.groupdict()['interface_vlan']
                interface_vlan = self._normalize_vlan(interface_vlan)
                continue
            ip_address_pattern = '\s+IP address\s+(?P<ip_address>\S+),\ssubnet mask\s+(?P<ip_subnet_mask>\S+)'
            match_ip_address = re.match(ip_address_pattern, line)
            if match_ip_address:
                interface_ip_address = match_ip_address.groupdict()['ip_address'] + '/' + match_ip_address.groupdict()['ip_subnet_mask']
                if interface_ip_address.startswith('128.') or interface_ip_address.startswith('127.'):
                    continue
                interface = {
                    'name': interface_name,
                    'state': interface_state,
                    'ip_address': interface_ip_address,
                }
                data = self.get_ip_network(interface_ip_address)
                if data:
                    interface['ip_address'] = data['ip_address']
                    interface['ip_network'] = data['ip_network']
                    interface['prefix_len'] = int(data['prefix_len'])
                if interface_alias:
                    if interface_alias != '':
                        interface['alias'] = interface_alias
                if interface_mac_address:
                    interface['mac_address'] = self._normalize_mac_address(interface_mac_address)
                if interface_mtu:
                    interface['mtu'] = interface_mtu
                if interface_description:
                    interface['description'] = interface_description
                    if re.search('[Ff]ailover [Ii]nterface', interface_description):
                        continue
                if interface_vlan:
                    interface['vlan'] = interface_vlan
                interfaces.append(interface)
                continue
            self.log.info("unmatched line: %s" % (line))
        return interfaces

    def get_ip_interfaces(self, opts):
        interfaces = {}
        for h in self.data:
            conf = self.data[h]['conf']
            if conf['os'] in ['junos_qfx', 'junos_mx', 'cisco_asa', 'paloalto_panos']:
                fp = self.get_relevant_file('interfaces', conf['os'], self.data[h]['cli'])
                if not fp:
                    self.log.error('host %s does not have relevant files for ip interface extraction' % (h));
                    continue;
                fp = os.path.join(self.data[h]['data_dir'], fp)
                items = None
                if conf['os'] in ['junos_qfx', 'junos_mx']:
                    items = self.get_ip_interfaces_junos_qfx(fp)
                elif conf['os'] in ['cisco_asa']:
                    items = self.get_ip_interfaces_cisco_asa(fp)
                elif conf['os'] in ['paloalto_panos']:
                    items = self.get_ip_interfaces_paloalto_panos(fp)
                else:
                    pass
                if not items:
                    self.log.error('host %s did not return relevant data during interface extraction' % (h));
                    continue;
                if len(items) == 0:
                    self.log.error('host %s did not return interface data' % (h))
                    continue
                interfaces[h] = items
            else:
                self.log.error('host %s does not support ip interface extraction' % (h));
                continue
        output = []
        for h in interfaces:
            for interface in interfaces[h]:
                interface['host'] = h
                output.append(interface)
        item_props = [
            'host', 'name', 'ip_address', 'ip_network', 'prefix_len',
            'mac_address', 'mtu', 'vlan', 'type', 'state',
            'description', 'alias',
        ]
        if 'output_fmt' in opts:
            if opts['output_fmt'] == 'csv':
                lines = []
                lines.append(';'.join(item_props))
                for item in output:
                    line = []
                    for item_prop in item_props:
                        if item_prop in item:
                            line.append(str(item[item_prop]))
                        else:
                            line.append('')
                    lines.append(';'.join(line))
                return '\n'.join(lines) + '\n'
        return output

    def get_lldp_neighbors(self, opts={}):
        servers = {}
        for h in self.data:
            conf = self.data[h]['conf']
            #if conf['os'] in ['junos_qfx', 'junos_mx', 'cisco_asa', 'paloalto_panos']:
            if conf['os'] in ['junos_qfx', 'junos_mx']:
                fp = self.get_relevant_file('lldp_neighbors', conf['os'], self.data[h]['cli'])
                if not fp:
                    self.log.error('host %s does not have relevant files for LLDP neighbor extraction' % (h));
                    servers[h] = [{'host': h, 'neighbor': 'NONE'}]
                    continue;
                fp = os.path.join(self.data[h]['data_dir'], fp)
                items = None
                if conf['os'] in ['junos_qfx', 'junos_mx']:
                    items = self.get_lldp_neighbors_junos_qfx(fp)
                elif conf['os'] in ['cisco_asa']:
                    items = self.get_lldp_neighbors_cisco_asa(fp)
                elif conf['os'] in ['paloalto_panos']:
                    items = self.get_lldp_neighbors_paloalto_panos(fp)
                else:
                    pass
                if not items:
                    self.log.error('host %s did not return relevant data during data extraction' % (h));
                    servers[h] = [{'host': h, 'neighbor': 'NONE'}]
                    continue;
                if len(items) == 0:
                    self.log.error('host %s did not return LLDP neighbor data' % (h))
                    servers[h] = [{'host': h, 'neighbor': 'NONE'}]
                    continue
                servers[h] = items
            else:
                self.log.error('host %s does not support LLDP neighbor extraction' % (h));
                continue
        output = []
        for h in servers:
            for entry in servers[h]:
                entry['host'] = h
                output.append(entry)
        if 'output_fmt' in opts:
            if opts['output_fmt'] == 'csv':
                lines = []
                item_props = ['host', 'neighbor', 'local_interface', 'local_parent_interface', 'neighbor_interface']
                lines.append(';'.join(item_props))
                for item in output:
                    line = []
                    for item_prop in item_props:
                        if item_prop in item:
                            line.append(str(item[item_prop]))
                        else:
                            line.append('')
                    lines.append(';'.join(line))
                return '\n'.join(lines) + '\n'
        return output

    def get_ospf_neighbors(self, opts={}):
        servers = {}
        for h in self.data:
            conf = self.data[h]['conf']
            #if conf['os'] in ['junos_qfx', 'junos_mx', 'cisco_asa', 'paloalto_panos']:
            if conf['os'] in ['junos_qfx', 'junos_mx']:
                fp = self.get_relevant_file('ospf_neighbors', conf['os'], self.data[h]['cli'])
                if not fp:
                    self.log.error('host %s does not have relevant files for OSPF neighbor extraction' % (h));
                    servers[h] = [{'host': h, 'router_id': 'NONE'}]
                    continue;
                fp = os.path.join(self.data[h]['data_dir'], fp)
                items = None
                if conf['os'] in ['junos_qfx', 'junos_mx']:
                    items = self.get_ospf_neighbors_junos_qfx(fp)
                elif conf['os'] in ['cisco_asa']:
                    items = self.get_ospf_neighbors_cisco_asa(fp)
                elif conf['os'] in ['paloalto_panos']:
                    items = self.get_ospf_neighbors_paloalto_panos(fp)
                else:
                    pass
                if not items:
                    self.log.error('host %s did not return relevant data during data extraction' % (h));
                    servers[h] = [{'host': h, 'router_id': 'NONE'}]
                    continue;
                if len(items) == 0:
                    self.log.error('host %s did not return OSPF neighbor data' % (h))
                    servers[h] = [{'host': h, 'router_id': 'NONE'}]
                    continue
                servers[h] = items
            else:
                self.log.error('host %s does not support OSPF neighbor extraction' % (h));
                continue
        output = []
        for h in servers:
            for entry in servers[h]:
                entry['host'] = h
                output.append(entry)
        if 'output_fmt' in opts:
            if opts['output_fmt'] == 'csv':
                lines = []
                item_props = ['host', 'router_id', 'address', 'adjacent', 'area', 'bdr', 'dr', 'interface', 'link_state_retransmission_list', 'opt', 'pri',  'state', 'up']
                lines.append(';'.join(item_props))
                for item in output:
                    line = []
                    for item_prop in item_props:
                        if item_prop in item:
                            line.append(str(item[item_prop]))
                        else:
                            line.append('')
                    lines.append(';'.join(line))
                return '\n'.join(lines) + '\n'
        return output


    def get_ntp_servers(self, opts={}):
        servers = {}
        for h in self.data:
            conf = self.data[h]['conf']
            #if conf['os'] in ['junos_qfx', 'junos_mx', 'cisco_asa', 'paloalto_panos']:
            if conf['os'] in ['junos_qfx', 'junos_mx']:
                fp = self.get_relevant_file('ntp_servers', conf['os'], self.data[h]['cli'])
                if not fp:
                    self.log.error('host %s does not have relevant files for NTP server extraction' % (h));
                    continue;
                fp = os.path.join(self.data[h]['data_dir'], fp)
                items = None
                if conf['os'] in ['junos_qfx', 'junos_mx']:
                    items = self.get_ntp_servers_junos_qfx(fp)
                elif conf['os'] in ['cisco_asa']:
                    items = self.get_ntp_servers_cisco_asa(fp)
                elif conf['os'] in ['paloalto_panos']:
                    items = self.get_ntp_servers_paloalto_panos(fp)
                else:
                    pass
                if not items:
                    self.log.error('host %s did not return relevant data during data extraction' % (h));
                    servers[h] = [{'host': h, 'ntp_server': 'NONE'}]
                    continue;
                if len(items) == 0:
                    self.log.error('host %s did not return NTP server data' % (h))
                    servers[h] = [{'host': h, 'ntp_server': 'NONE'}]
                    continue
                servers[h] = items
            else:
                self.log.error('host %s does not support NTP server extraction' % (h));
                continue
        output = []
        for h in servers:
            for entry in servers[h]:
                entry['host'] = h
                output.append(entry)
        if 'output_fmt' in opts:
            if opts['output_fmt'] == 'csv':
                lines = []
                item_props = ['host', 'ntp_server', 'reach', 'delay', 'jitter', 'offset', 'poll', 'refid', 'st', 'when']
                lines.append(';'.join(item_props))
                for item in output:
                    line = []
                    for item_prop in item_props:
                        if item_prop in item:
                            line.append(str(item[item_prop]))
                        else:
                            line.append('')
                    lines.append(';'.join(line))
                return '\n'.join(lines) + '\n'
        return output

    def get_aaa_servers(self, opts={}):
        servers = {}
        for h in self.data:
            conf = self.data[h]['conf']
            #if conf['os'] in ['junos_qfx', 'junos_mx', 'cisco_asa', 'paloalto_panos']:
            if conf['os'] in ['junos_qfx', 'junos_mx']:
                fp = self.get_relevant_file('aaa_servers', conf['os'], self.data[h]['cli'])
                if not fp:
                    self.log.error('host %s does not have relevant files for AAA server extraction' % (h));
                    continue;
                fp = os.path.join(self.data[h]['data_dir'], fp)
                items = None
                if conf['os'] in ['junos_qfx', 'junos_mx']:
                    items = self.get_aaa_servers_junos_qfx(fp)
                elif conf['os'] in ['cisco_asa']:
                    items = self.get_aaa_servers_cisco_asa(fp)
                elif conf['os'] in ['paloalto_panos']:
                    items = self.get_aaa_servers_paloalto_panos(fp)
                else:
                    pass
                if not items:
                    self.log.error('host %s did not return relevant data during data extraction' % (h));
                    continue;
                if len(items) == 0:
                    self.log.error('host %s did not return AAA server data' % (h))
                    continue
                servers[h] = items
            else:
                self.log.error('host %s does not support AAA server extraction' % (h));
                continue
        output = []
        for h in servers:
            for entry in servers[h]:
                entry['host'] = h
                output.append(entry)
        if 'output_fmt' in opts:
            if opts['output_fmt'] == 'csv':
                lines = []
                item_props = ['host', 'server', 'port', 'source-address', 'secret']
                lines.append(';'.join(item_props))
                for item in output:
                    line = []
                    for item_prop in item_props:
                        if item_prop in item:
                            line.append(str(item[item_prop]))
                        else:
                            line.append('')
                    lines.append(';'.join(line))
                return '\n'.join(lines) + '\n'
        return output

    def get_local_users(self, opts={}):
        servers = {}
        for h in self.data:
            conf = self.data[h]['conf']
            #if conf['os'] in ['junos_qfx', 'junos_mx', 'cisco_asa', 'paloalto_panos']:
            if conf['os'] in ['junos_qfx', 'junos_mx']:
                fp = self.get_relevant_file('local_users', conf['os'], self.data[h]['cli'])
                if not fp:
                    self.log.error('host %s does not have relevant files for local user data extraction' % (h));
                    continue;
                fp = os.path.join(self.data[h]['data_dir'], fp)
                items = None
                if conf['os'] in ['junos_qfx', 'junos_mx']:
                    items = self.get_local_users_junos_qfx(fp)
                elif conf['os'] in ['cisco_asa']:
                    items = self.get_local_users_cisco_asa(fp)
                elif conf['os'] in ['paloalto_panos']:
                    items = self.get_local_users_paloalto_panos(fp)
                else:
                    pass
                if not items:
                    self.log.error('host %s did not return relevant data during data extraction' % (h));
                    continue;
                if len(items) == 0:
                    self.log.error('host %s did not return local user data' % (h))
                    continue
                servers[h] = items
            else:
                self.log.error('host %s does not support local user extraction' % (h));
                continue
        output = []
        for h in servers:
            for entry in servers[h]:
                entry['host'] = h
                output.append(entry)
        if 'output_fmt' in opts:
            if opts['output_fmt'] == 'csv':
                lines = []
                item_props = ['host', 'username', 'class', 'authentication']
                lines.append(';'.join(item_props))
                for item in output:
                    line = []
                    for item_prop in item_props:
                        if item_prop in item:
                            line.append(str(item[item_prop]))
                        else:
                            line.append('')
                    lines.append(';'.join(line))
                return '\n'.join(lines) + '\n'
        return output

    def get_syslog_servers(self, opts={}):
        servers = {}
        for h in self.data:
            conf = self.data[h]['conf']
            #if conf['os'] in ['junos_qfx', 'junos_mx', 'cisco_asa', 'paloalto_panos']:
            if conf['os'] in ['junos_qfx', 'junos_mx']:
                fp = self.get_relevant_file('syslog_servers', conf['os'], self.data[h]['cli'])
                if not fp:
                    self.log.error('host %s does not have relevant files for syslog server extraction' % (h));
                    continue;
                fp = os.path.join(self.data[h]['data_dir'], fp)
                items = None
                if conf['os'] in ['junos_qfx', 'junos_mx']:
                    items = self.get_syslog_servers_junos_qfx(fp)
                elif conf['os'] in ['cisco_asa']:
                    items = self.get_syslog_servers_cisco_asa(fp)
                elif conf['os'] in ['paloalto_panos']:
                    items = self.get_syslog_servers_paloalto_panos(fp)
                else:
                    pass
                if not items:
                    self.log.error('host %s did not return relevant data during data extraction' % (h));
                    servers[h] = [{'host': h, 'destination': 'NONE'}]
                    continue;
                if len(items) == 0:
                    self.log.error('host %s did not return syslog server data' % (h))
                    servers[h] = [{'host': h, 'destination': 'NONE'}]
                    continue
                servers[h] = items
            else:
                self.log.error('host %s does not support syslog server extraction' % (h));
                continue
        output = []
        for h in servers:
            for entry in servers[h]:
                entry['host'] = h
                output.append(entry)
        if 'output_fmt' in opts:
            if opts['output_fmt'] == 'csv':
                lines = []
                item_props = ['host', 'destination']
                lines.append(';'.join(item_props))
                for item in output:
                    line = []
                    for item_prop in item_props:
                        if item_prop in item:
                            line.append(str(item[item_prop]))
                        else:
                            line.append('')
                    lines.append(';'.join(line))
                return '\n'.join(lines) + '\n'
        return output

    def get_snmp_servers(self, opts={}):
        servers = {}
        for h in self.data:
            conf = self.data[h]['conf']
            #if conf['os'] in ['junos_qfx', 'junos_mx', 'cisco_asa', 'paloalto_panos']:
            if conf['os'] in ['junos_qfx', 'junos_mx']:
                fp = self.get_relevant_file('snmp_servers', conf['os'], self.data[h]['cli'])
                if not fp:
                    self.log.error('host %s does not have relevant files for snmp server extraction' % (h));
                    continue;
                fp = os.path.join(self.data[h]['data_dir'], fp)
                items = None
                if conf['os'] in ['junos_qfx', 'junos_mx']:
                    items = self.get_snmp_servers_junos_qfx(fp)
                elif conf['os'] in ['cisco_asa']:
                    items = self.get_snmp_servers_cisco_asa(fp)
                elif conf['os'] in ['paloalto_panos']:
                    items = self.get_snmp_servers_paloalto_panos(fp)
                else:
                    pass
                if not items:
                    self.log.error('host %s did not return relevant data during data extraction' % (h));
                    continue;
                if len(items) == 0:
                    self.log.error('host %s did not return snmp server data' % (h))
                    continue
                servers[h] = items
            else:
                self.log.error('host %s does not support snmp server extraction' % (h));
                continue
        output = []
        for h in servers:
            for entry in servers[h]:
                entry['host'] = h
                output.append(entry)
        if 'output_fmt' in opts:
            if opts['output_fmt'] == 'csv':
                lines = []
                item_props = ['host', 'prop', 'value']
                lines.append(';'.join(item_props))
                for item in output:
                    line = []
                    _found = False
                    if 'trap_groups' in item:
                        for group in item['trap_groups']:
                            if 'targets' not in item['trap_groups'][group]:
                                continue
                            if len(item['trap_groups'][group]['targets']) == 0:
                                continue
                            _found = True
                            for target in sorted(item['trap_groups'][group]['targets']):
                                lines.append(';'.join([item['host'], 'trap_destination', target]))
                    if not _found:
                        lines.append(';'.join([item['host'], 'trap_destination', 'NONE']))
                    for f in ['contact', 'description', 'location']:
                        if f in item:
                            lines.append(';'.join([item['host'], f, item[f]]))
                        else:
                            lines.append(';'.join([item['host'], f, 'NONE']))
                    _found = False
                    if 'communities' in item:
                        for c in item['communities']:
                            if 'authorization' in item['communities'][c]:
                                lines.append(';'.join([item['host'], 'snmp_community', c + '(' +  ' '.join(item['communities'][c]['authorization']) + ')']))
                                _found = True
                    if not _found:
                        lines.append(';'.join([item['host'], 'snmp_community', 'NONE']))

                return '\n'.join(lines) + '\n'
        return output

    def get_interface_props(self, opts={}):
        interfaces = {}
        for h in self.data:
            conf = self.data[h]['conf']
            #if conf['os'] in ['junos_qfx', 'junos_mx', 'cisco_asa', 'paloalto_panos']:
            if conf['os'] in ['junos_qfx', 'junos_mx']:
                fp = self.get_relevant_file('interfaces', conf['os'], self.data[h]['cli'])
                if not fp:
                    self.log.error('host %s does not have relevant files for interface properties extraction' % (h));
                    continue;
                fp = os.path.join(self.data[h]['data_dir'], fp)
                items = None
                if conf['os'] in ['junos_qfx', 'junos_mx']:
                    items = self.get_interface_props_junos_qfx(fp)
                elif conf['os'] in ['cisco_asa']:
                    items = self.get_interface_props_cisco_asa(fp)
                elif conf['os'] in ['paloalto_panos']:
                    items = self.get_interface_props_paloalto_panos(fp)
                else:
                    pass
                if not items:
                    self.log.error('host %s did not return relevant data during interface extraction' % (h));
                    continue;
                if len(items) == 0:
                    self.log.error('host %s did not return interface data' % (h))
                    continue
                interfaces[h] = items
            else:
                self.log.error('host %s does not support interface properties extraction' % (h));
                continue
        output = []
        for h in interfaces:
            for interface in interfaces[h]:
                interface['host'] = h
                output.append(interface)

        if 'output_fmt' in opts:
            if opts['output_fmt'] == 'csv':
                lines = []
                lines.append(';'.join(['host', 'interface_name', 'property', 'value']))
                for item in output:
                    if 'host' not in item:
                        continue
                    if 'interface_name' not in item:
                        continue
                    for k in sorted(item):
                        line = []
                        line.append(item['host'])
                        line.append(item['interface_name'])
                        if k in ['host', 'interface_name']:
                            continue
                        line.append(k)
                        line.append(str(item[k]))
                        lines.append(';'.join(line))
                return '\n'.join(lines) + '\n'
        return output

    def get_arp_entries_junos_qfx(self,fp):
        return self.get_arp_entries_junos(fp)

    def get_arp_entries_junos(self,fp):
        entries = []
        self.log.info("get_arp_entries_junos(): %s" % (fp))
        patterns = [
            '^([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}'
        ]
        lines = self.get_file_contents(fp, patterns)
        for line in lines:
            match_arp_entry = re.match('^(?P<mac_address>([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2})\s+(?P<ip_address>(\d{1,3}\.){3}\d{1,3})\s+(?P<interface>\S+)\s+', line)
            if match_arp_entry:
                entry = {
                    'mac_address': self._normalize_mac_address(match_arp_entry.groupdict()['mac_address']),
                    'ip_address': match_arp_entry.groupdict()['ip_address'],
                    'interface': match_arp_entry.groupdict()['interface'],
                }
                entries.append(entry)
                continue
            self.log.info("unmatched line: %s" % (line))
        return entries

    def get_arp_entries_cisco_asa(self,fp):
        entries = []
        self.log.info("get_arp_entries_cisco_asa(): %s" % (fp))
        patterns = [
            '.*([A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4}'
        ]
        lines = self.get_file_contents(fp, patterns)
        for line in lines:
            arp_entry = re.match('^\s*(?P<interface>\S+)\s+(?P<ip_address>(\d{1,3}\.){3}\d{1,3})\s+(?P<mac_address>([A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4})\s+', line)
            if arp_entry:
                entry = {
                    'mac_address': self._normalize_mac_address(arp_entry.groupdict()['mac_address']),
                    'ip_address': arp_entry.groupdict()['ip_address'],
                    'interface': arp_entry.groupdict()['interface'],
                }
                entries.append(entry)
                continue
            self.log.info("unmatched line: %s" % (line))
        return entries

    def get_arp_entries_paloalto_panos(self,fp):
        entries = []
        self.log.info("get_arp_entries_paloalto_panos(): %s" % (fp))
        patterns = [
            '.*([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}'
        ]
        lines = self.get_file_contents(fp, patterns)
        for line in lines:
            arp_entry = re.match('^(?P<interface>\S+)\s+(?P<ip_address>(\d{1,3}\.){3}\d{1,3})\s+(?P<mac_address>([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2})\s+', line)
            if arp_entry:
                entry = {
                    'mac_address': self._normalize_mac_address(arp_entry.groupdict()['mac_address']),
                    'ip_address': arp_entry.groupdict()['ip_address'],
                    'interface': arp_entry.groupdict()['interface'],
                }
                entries.append(entry)
                continue
            self.log.info("unmatched line: %s" % (line))
        return entries


    def get_arp_entries(self, opts={}):
        _resolve_mac_vendor = False
        if 'resolve_mac_vendor' in opts:
            _resolve_mac_vendor = opts['resolve_mac_vendor']
            if 'mac_vendor_file' in opts:
                self._load_oui_ref(opts['mac_vendor_file'])
        arp_entries = {}
        for h in self.data:
            conf = self.data[h]['conf']
            if conf['os'] in ['junos_qfx', 'junos_mx', 'cisco_asa', 'paloalto_panos']:
                fp = self.get_relevant_file('arp_entries', conf['os'], self.data[h]['cli'])
                if not fp:
                    self.log.error('host %s does not have relevant files for ARP table extraction' % (h));
                    continue;
                fp = os.path.join(self.data[h]['data_dir'], fp)
                items = None
                if conf['os'] in ['junos_qfx', 'junos_mx']:
                    items = self.get_arp_entries_junos_qfx(fp)
                elif conf['os'] in ['cisco_asa']:
                    items = self.get_arp_entries_cisco_asa(fp)
                elif conf['os'] in ['paloalto_panos']:
                    items = self.get_arp_entries_paloalto_panos(fp)
                else:
                    pass
                if not items:
                    self.log.error('host %s did not return relevant data during ARP table extraction' % (h));
                    continue;
                if len(items) == 0:
                    self.log.error('host %s did not return ARP table data' % (h))
                    continue
                arp_entries[h] = items
            else:
                self.log.error('host %s does not support ARP table extraction' % (h));
                continue
        output = []
        item_props = ['host', 'interface', 'mac_address', 'ip_address']
        if _resolve_mac_vendor:
            item_props.append('mac_vendor')
        for h in arp_entries:
            for arp_entry in arp_entries[h]:
                arp_entry['host'] = h
                for k in arp_entry:
                    if k not in item_props:
                        item_props.append(k)
                if _resolve_mac_vendor:
                    vendor = self._get_mac_vendor(arp_entry['mac_address'])
                    if vendor:
                        arp_entry['mac_vendor'] = vendor
                    else:
                        arp_entry['mac_vendor'] = 'UNKNOWN'
                output.append(arp_entry)
        if 'output_fmt' in opts:
            if opts['output_fmt'] == 'csv':
                lines = []
                lines.append(';'.join(item_props))
                for item in output:
                    line = []
                    for item_prop in item_props:
                        if item_prop in item:
                            line.append(str(item[item_prop]))
                        else:
                            line.append('')
                    lines.append(';'.join(line))
                return '\n'.join(lines) + '\n'
        return output

    def get_device_info(self, opts={}):
        items = []
        item_conf_props = [
            'host', 'os', 'host_overwrite',
        ]
        item_fact_props = []
        for h in self.data:
            data = self.data[h]
            item = {}
            if 'conf' not in data:
                continue
            for key in ['host', 'os', 'host_overwrite']:
                if key in data['conf']:
                    item['conf_' + key] = data['conf'][key]
            if 'facts' in data:
                for key in data['facts']:
                    if key not in item_fact_props:
                        item_fact_props.append(key)
                    item['fact_' + key] = data['facts'][key]
            items.append(item)
        item_props = []
        for key in item_conf_props:
            item_props.append('conf_' + key)
        for key in item_fact_props:
            item_props.append('fact_' + key)
        if 'output_fmt' in opts:
            if opts['output_fmt'] == 'csv':
                lines = []
                lines.append(';'.join(item_props))
                for item in items:
                    line = []
                    for item_prop in item_props:
                        if item_prop in item:
                            line.append(str(item[item_prop]))
                        else:
                            line.append('')
                    lines.append(';'.join(line))
                return '\n'.join(lines) + '\n'
        return items

    @staticmethod
    def get_ip_network(s):
        arr = s.split('/')
        if len(arr) == 2:
            if len(arr[1]) > 2:
                try:
                    prefix = ipaddress.IPv4Network('0.0.0.0/' + unicode(arr[1]) ).prefixlen
                    s = arr[0] + '/' + str(prefix)
                except:
                    pass
        try:
            response = {}
            interface = ipaddress.IPv4Interface(unicode(s))
            response = {
                'ip_address': str(interface.with_prefixlen),
                'ip_network': str(interface.network)
            }
            response['prefix_len'] = int(response['ip_address'].split('/')[1])
            response['ip_address'] = response['ip_address'].split('/')[0]
            return response
        except:
            return None
        return None

    @staticmethod
    def _normalize_mac_address(s):
        s = s.lower().replace(':', '').replace('.', '')
        #for i in [2, 5, 8, 11, 14]:
        #    s = s[:i] + ':' + s[i:]
        return s

    def _get_mac_vendor(self, s):
        if len(s) < 8:
            return None
        if s[:6] in self.oui_ref:
            return self.oui_ref[s[:6]]
        return None

    def _load_oui_ref(self, f):
        self.log.debug('loading OUI Reference file: %s' % (f.name));
        lines = f.readlines();
        self.oui_ref = {}
        for line in lines:
            oui_rgx = re.match('(.*)\(hex\)(.*)', line);
            if oui_rgx:
                oui_id = str(oui_rgx.group(1)).strip().replace('-', '').lower();
                self.oui_ref[oui_id] = re.sub(r'[^\x00-\x7f]', r'', str(oui_rgx.group(2)).strip());
        self.log.debug('loaded OUI Reference file: %s' % (f.name));
        return

    @staticmethod
    def get_column_map(s):
        ''' This function takes in the header from cli output, and builds a field map '''
        space_count = 0
        columns = None
        k = 0
        j = 0
        for i, c in enumerate(s):
            if c == ' ':
                space_count += 1
            else:
                if space_count >= 2:
                    if not columns:
                        columns = []
                    columns.append({
                        'end': i,
                        'start': j,
                        'name': str(s[j:i]).strip().lower().replace(' ', '_'),
                    })
                    k += 1
                    j = i
                space_count = 0
        columns.append({
            'start': j,
            'name': str(s[j:]).strip().lower().replace(' ', '_'),
        })
        return columns

    @staticmethod
    def get_column_data(column_map, line):
        resp = {}
        ln = len(line)
        for m in column_map:
            if ln < m['start']:
                continue
            if 'end' in m:
                if ln > m['end']:
                    resp[m['name']] = str(line[m['start']:m['end']]).strip()
                    continue
                resp[m['name']] = str(line[m['start']:]).strip()
        return resp


    @staticmethod
    def _normalize_vlan(s):
        try:
            i = int(s)
            return i
        except:
            return None
        return None

    @staticmethod
    def _normalize_mtu(s):
        try:
            i = int(s)
            return i
        except:
            return None
        return None

    def _remove_unicode(self, data):
        if isinstance(data, (dict)):
            new_data = {}
            for k in data:
                if isinstance(k, (unicode)):
                    new_data[str(k)] = self._remove_unicode(data[k])
                    continue
                new_data[k] = self._remove_unicode(data[k])
            return new_data
        if isinstance(data, (list)):
            new_data = []
            for entry in data:
                new_data.append(self._remove_unicode(entry))
            return new_data
        elif isinstance(data, (unicode)):
            s = ''
            try:
                s = str(data)
            except:
                s = ''.join([i if ord(i) < 128 else ' ' for i in data])
            return str(s)
        elif isinstance(data, (long)):
            return str(data)
        elif isinstance(data, (datetime)):
            return (data - datetime(1970,1,1)).total_seconds()
        else:
            pass
        return data

    @staticmethod
    def is_addr_in_network(ip, net):

        '''
        ipv4_net = ipaddress.IPv4Network(unicode(net))
        ipv4_addr = ipaddress.IPv4Network(unicode(ip) + '/32')
        if ipv4_net.overlaps(ipv4_addr):
            return True
        return False
        '''

        '''
        ipaddr_bin = struct.unpack('!I', socket.inet_pton(socket.AF_INET, ip))[0]
        net_addr, net_mask = net.split('/')
        net_mask_bin = ((2L<<int(net_mask)-1) - 1)
        net_addr_bin = struct.unpack('!I',socket.inet_aton(net_addr))[0]
        if (ipaddr_bin & net_mask_bin) == net_addr_bin:
            return True
        return False
        '''

        ipv4_net = ipaddress.ip_network(unicode(net))
        ipv4_addr = int(ipaddress.ip_address(unicode(ip)))
        return (ipv4_addr & int(ipv4_net.netmask)) == int(ipv4_net.network_address)

    def get_edge_discovery(self, opts={}):
        networks = {}
        arp_entries = {}
        if 'ip_interface_ref' in opts:
            entries = json.load(opts['ip_interface_ref'])
            for entry in entries:
                if 'ip_network' not in entry:
                    continue
                if 'prefix_len' not in entry:
                    continue
                n = entry['ip_network']
                if n not in networks:
                    networks[n] = {
                        'nodes': [],
                        'count': 0,
                    }
                networks[n]['nodes'].append(entry)
                networks[n]['count'] += 1
                networks[n]['prefix_len'] = entry['prefix_len']

        '''
        Determine the host relevant to the discovery.
        '''
        target_hosts = []
        target_networks = []

        for n in networks:
            if networks[n]['count'] > 1:
                continue
            if networks[n]['prefix_len'] < 29:
                continue
            for entry in networks[n]['nodes']:
                if 'host' not in entry:
                    continue
                if entry['host'] not in target_hosts:
                    target_hosts.append(entry['host'])
            if n not in target_networks:
                target_networks.append(n)
            #pprint.pprint(networks[n])

        if 'arp_table_ref' in opts:
            entries = json.load(opts['arp_table_ref'])
            for entry in entries:
                if 'ip_address' not in entry:
                    continue
                if 'host' not in entry:
                    continue
                h = entry['host']
                if h not in target_hosts:
                    continue
                if h not in arp_entries:
                    arp_entries[h] = []
                arp_entries[h].append(entry)

        networks = self._remove_unicode(networks)
        arp_entries = self._remove_unicode(arp_entries)

        edge_nodes = {}
        for n in networks:
            if n not in target_networks:
                continue
            for entry in networks[n]['nodes']:
                h = entry['host']
                #self.log.error('Found potential edge node %s' % entry)
                if h not in edge_nodes:
                    edge_nodes[h] = []
                intf = entry
                intf['arp_entries'] = []
                if h in arp_entries:
                    for arp_entry in arp_entries[h]:
                        if self.is_addr_in_network(arp_entry['ip_address'], n):
                            intf['arp_entries'].append(arp_entry)
                            self.log.error('ip %s is in %s' % (arp_entry['ip_address'], n))
                edge_nodes[h].append(intf)
        if 'output_fmt' in opts:
            if opts['output_fmt'] == 'csv':
                lines = []
                for h in edge_nodes:
                    lines.append('')
                    lines.append('host: %s' % (h))
                    for n in edge_nodes[h]:
                        lines.append('  interface: %s (ip address: %s, network: %s, MAC: %s)' % (n['name'], n['ip_address'], n['ip_network'], n['mac_address']))
                        if 'state' in n:
                            if n['state'] != 'up':
                                lines.append('    Removal candidate. Status: %s' % (n['state']))
                                continue
                        if 'arp_entries' in n:
                            if len(n['arp_entries']) > 0:
                                for entry in n['arp_entries']:
                                    lines.append('    arp entry: interface %s, IP: %s, MAC: %s (%s)' % (entry['interface'],
                                        entry['ip_address'], entry['mac_address'], entry['mac_vendor']))
                            else:
                                lines.append('    No ARP entries')
                return '\n'.join(lines) + '\n'
        return edge_nodes

if __name__ == '__main__':
    raise Exception('This is not a script. Direct access is not suppported.');
