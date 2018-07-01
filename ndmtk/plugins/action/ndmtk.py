# -*- coding: utf-8 -*-

#
# ndmtk - Network Discovery and Management Toolkit
# Copyright (C) 2016 Paul Greenberg @greenpau
# See LICENSE.txt for licensing details
#

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: ndmtk
short_description: Interacts with network devices, collects and analyzes network data.
author: "Paul Greenberg (@greenpau)"
description:
    - The C(ndmtk) plugin interacts with remote network devices. It can collect
      data and analyze data, perform sophisticated configuration or additional
      data collection.
    - The C(ndmtk) plugin has no required arguments, because there are
      a number of default commands available for various operating systems,
      e.g. Cisco Nexus OS, Arista EOS, Linux, etc.
    - The C(ndmtk) plugin determines the commands to run on a remote
      network device by analyzing pre-packaged commands. The commands, conditions,
      and other logic are stored in YAML files. A user may supply custom
      configuration and/or data collection instructions in YAML files.
      Moreover, a user may supply a list of commands that should never run
      on a devices.
    - The C(ndmtk) plugin uses ansible vault to store access credentials.
options:
    disable_defaults:
        description:
        - Disables default pre-packages commands for various operating systems,
          e.g. Cisco Nexus OS, Arista EOS, Linux, etc.
        required: false
        default: False
        choices: [ yes, no ]
    sections:
        description:
        - Instructs the plugin to only run the commands associated with the
          sections listed in this option. A user may specify multiple sections
          by using comma as a delimeter.
        - For example, if the only section listed is C(bgp), then the
          plugin will only run the commands necessary to determine active
          configuration, version information, and relevant BGP commands.
          For a Cisco router, the plugin will run C(show running configuration),
          C(show version) and then if it finds BGP configured on the device,
          the plugin will run C(show ip bgp), C(show ip bgp summary), etc.
          Subsequently, if the plugin find BGP neighbors, it run additional
          commands, e.g. C(show ip bgp neighbor <neighbor_ip> details), etc.
        required: false
    cliset_os_dir:
        description:
        - The path to YAML files containing user-defined commands on per operating
          system basis. The plugin will run the commands only if the plugin is able to
          locate a file matching a remote host's operating system in this
          directory.
        - For example, if a host's operating system is C(cisco_nxos), the plugin
          will look for C(cisco_nxos.yml) file in this directory. If the file is
          found, then the plugin will run the commands it found in the file.
          Please note that the plugin runs the commands in addition to any default
          commands, unless they are disabled with C(disable_defaults).
        - The default commands for various operating systems are located in
          C(<python_site_packages>/ndmtk/files/cli/os).
        required: false
        default: C(<ansible_inventory_dir>/files/ndmtk/os/) directory
    cliset_host_dir:
        description:
        - The path to YAML files containing user-defined commands on per host
          basis. The plugin will run the commands only if the plugin is able to
          locate a file matching a remote host's hostname in this
          directory.
        - For example, if a host's hostname is C(ny-fw01), the plugin
          will look for C(ny-fw01.yml) file in this directory. If the file is
          found, then the plugin will run the commands it found in the file.
          Please note that the plugin runs the commands in addition to any default
          commands, unless they are disabled with C(disable_defaults).
        required: false
        default: "C(<ansible_inventory_dir>/files/ndmtk/host/) directory"
    cliset_spec:
        description:
        - The path to a single YAML file containing user-defined commands.
        - As with the above options, the plugin runs the commands in addition to
          any default commands, unless they are disabled with C(disable_defaults).
        required: false
        default: "C(None)"
    cliset_exc:
        description:
        - The path to a single YAML file containing exceptions both default
          and user defined commands. The root element of the YAML data structure
          is C(exceptions). The structure is a list of dictionaries/items.
          Each dictionary item must have at least one of the keys: C(cli),
          C(host), and/or C(os). The keys are strings containing regular
          expressions.
        - The plugin pre-checks each of the commands it has in its queue
          against the exceptions. If the plugin matches a command with
          the C(cli) regular expression, it performs additional C(host) and
          C(os) regular expression searches, if any. If the plugin is able
          to match all regular expressions within a single exception, it
          marks the command as C(skipped) and never runs it on the actual
          device.
        required: false
        default: "C(<ansible_inventory_dir>/files/ndmtk/exceptions.yml) file""
    output:
        description:
        - The plugin uses the value supplied with this option to determine
          where to store the data produced by the plugin.
        - If a path contains C(%) sign in it, then the plugin performs pre-defined
          conversions. For example, C(%h) is converted to a host's hostname,
          C(%H) to a host's FQDN, and C(%E) to epoch timestamp.
        - Please search the plugin's source code for the full list of converted
          characters.
        aliases: [ output_dir ]
        required: false
        default: "C(None)"
    on_error:
        description:
        - The plugin uses this option to determine what to do when a command
          produces an error.
        required: false
        default: abort
        choices: [ continue, abort ]
    on_prompt:
        description:
        - The plugin uses this option to determine what to do when a command
          produces Yes/No prompt, e.g. Do you want to continue? If C(continue),
          then the plugin, will responds with an affirmation.
        required: false
        default: abort
        choices: [ continue, abort ]
    identity:
        description:
        - The plugin stores information in directories and files. Each node
          receives a subdirectory inside the C(output) directory. The name of
          the directory is either host's hostname or FQDN. If the value is
          C(short), then ansible's C(inventory_hostname_short) variable
          (hostname) is used. If the value is C(fqdn), then ansible's
          C(inventory_hostname_short) variable (FQDN) is used.
        required: false
        default: short
        choices: [ short, fqdn ]
    no_host_key_check:
        description:
        - Instructs the plugin to accept SSH fingerprints without validation,
          i.e. trust any fingerprint.
        required: false
        default: no
        choices: [ yes, no ]
    debug:
        description:
        - Enable debugging for the plugin.
        required: false
        default: no
        choices: [ yes, no ]
    show_tech:
        description:
        - Allows the collection of C(show tech)-type commands. These commands
          could produce MBs of output data, e.g. C(show tech-support). The
          commands are tagged with the tag C(tech-support).
        required: false
        default: no
        choices: [ yes, no ]
    safe:
        description:
        - The path to Ansible Vault file. It contains authentication credentials
          to managed devices and jumphosts.
        required: false
        default: "~/.ansible.vault.yml"
    lockpick:
        description:
        - The path to the passwords used to unlock ansible vaults.
        required: false
        default: "~/.ansible.vault.key"
    jumphosts:
        description:
        - The chain of jumphosts to access managed hosts, i.e. ansible
          will not access managed hosts directly.
        aliases: ['jumphost']
        required: false
        default: "C(None)"
notes:
    - Please open issues in the plugin's Github repository for any questions
      associated with the use of the plugin.
'''

EXAMPLES = r'''
# Runs default commands and stores them in the output directory,
# The `%Y%m%d` converts to year, month, and date
- name: collect data from network nodes
  action: ndmtk output="/tmp/data-%Y%m%d"

# Runs default commands and stores output in /opt/data directory.
# Accepts SSH fingerprints without validation.
- name: collect data from network nodes
  action: ndmtk output="/tmp/data" no_host_key_check=yes

# Runs default commands and stores them in /tmp/data directory.
# The authentication credentials for the task are located
# in /opt/admin/auth.yml
- name: collect data from network nodes
  action: ndmtk output="/tmp/data" safe="/opt/admin/auth.yml"

# Here, the password for the vault is located in /opt/admin/unlock.key
# The authentication credentials for the task are located
# in /opt/admin/auth.yml
- name: collect data from network nodes
  action: ndmtk output="/tmp/data" safe="/opt/admin/auth.yml" lockpick="/opt/admin/unlock.key"

# This data collection is performed via a number of jump hosts.
# The plugin will hop to the managed host via the below chain or devices,
# i.e. `controller` => `10.1.1.1`, `10.1.1.1` => `10.1.2.3`, `10.1.2.3` => `10.2.3.4` => `managed node`
- name: data collection via jumphosts
  action: ndmtk output="/tmp/data-test-%Y%m%d%H%M%S" jumphosts="10.1.1.1,10.1.2.3,10.2.3.4" no_host_key_check=yes

# This data collection task gathers configuration ans version information only.
# If the plugin receives an error from a remote system, it will not abort its execution.
- name: collect running configuration ond version only
  action: ndmtk output="/opt/data/ansible/poc-conf-%Y%m%d%H%M%S" sections="configuration, version" no_host_key_check=yes on_error=continue
'''

RETURN = r'''
msg:
    description: changed
    returned: always
    type: boolean
    sample: True
junit:
    description: The path to a JUnit file containing a report
    returned: success
    type: string
    sample: /opt/data/ny-fw01/ny-fw01.junit.xml
log_dir:
    description: The path to a temporary log directory
    returned: always
    type: string
    sample: /home/greenpau/.ansible/tmp/f044da23-d126-11e6-858a-f45c89b1bb39/f08a836b-d126-11e6-ae84-f45c89b1bb39/ny-fw01
data_dir
    description: The path to the directory containing the data collected during a task
    returned: success
    type: string
    sample: /opt/data/20161212/ny-fw01
'''

import os;
import sys;
import re;
import tempfile;
import hashlib;
import pprint;
import traceback;
import yaml;
import datetime;
import errno;
import stat;
from collections import OrderedDict;
try:
    from ansible import constants as C;
except:
    pass
from ansible.errors import AnsibleError;
from ansible.plugins.action import ActionBase;
try:
    from ansible.module_utils.parsing.convert_bool import boolean
except ImportError:
    try:
        from ansible.utils.boolean import boolean
    except ImportError:
        try:
            from ansible.utils import boolean
        except ImportError:
            from ansible import constants
            boolean = constants.mk_boolean
from datetime import date;
import jinja2;
import json;
import time;
import uuid;
import signal;
import copy;
try:
    from __main__ import display;
except ImportError:
    from ansible.utils.display import Display;
    display = Display();

class ActionModule(ActionBase):

    def _indent(self, i=0, spacing=' '):
        if i != 0:
            return i * spacing;
        else:
            return "";

    def signal_handler(self, signum, stack_frame):
        '''
        TODO: fix interrupt signaling
        '''
        exc_type, exc_value, exc_traceback = sys.exc_info();
        self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
        display.display(str(self.errors));
        display.display('signal:' + self.signals[signum] + '\ncurrent pid: ' + str(os.getpid()) + '\n' + str(os.getenv) + str(os.ctermid()), color='yellow');
        return

    def run(self, tmp=None, task_vars=None):
        '''
        This plugin interracts with network devices via expect wrapper for SSH,
        Telnet, console, and any other form of command-line interface.
        '''

        self.signals = dict((k, v) for v, k in reversed(sorted(signal.__dict__.items())) if v.startswith('SIG') and not v.startswith('SIG_'));
        signal.signal(signal.SIGINT, self.signal_handler);

        self.plugin_file = str(__file__).rstrip('c');
        if os.path.islink(self.plugin_file):
            self.plugin_root = '/'.join(os.path.realpath(self.plugin_file).split('/')[:-1]);
        else:
            self.plugin_root = '/'.join(os.path.abspath(__file__).split('/')[:-1]);
        self.plugin_name = os.path.splitext(os.path.basename(__file__))[0];
        self.plugin_j2 = os.path.join(self.plugin_root, self.plugin_name) + '.j2';
        self.plugin_conf = os.path.join(self.plugin_root, self.plugin_name) + '.yml';

        self.errors = [];
        self.conf = dict();
        self.info = dict();
        self.status = dict();
        self.refdb = OrderedDict();
        self.refs = {};
        self.conf['time_start'] = int(round(time.time() * 1000));
        self.status['return_code'] = 0;
        self.status['return_status'] = 'pending';
        self.conf['cliset_last_id'] = 0;
        self.conf['abort'] = False;

        if task_vars is None:
            task_vars = dict();

        result = super(ActionModule, self).run(tmp, task_vars);

        for p in ['debug', 'show_tech', 'show_expect']:
            if p in ['show_expect']:
                self.conf[p] = boolean(self._task.args.get(p, 'yes'));
            else:
                self.conf[p] = boolean(self._task.args.get(p, 'no'))
            if not isinstance(self.conf[p], bool):
                raise AnsibleError("the '" + self.plugin_name + "' action's '" + p + "' argument must be either 'yes' or 'no'");

        self.ansible_root = task_vars.get('inventory_dir', None);
        if self.ansible_root is None:
            raise AnsibleError("failed to identify 'inventory_dir'");

        '''
        Discover host name.
        '''

        self.conf['identity'] = self._task.args.get('identity', 'short');
        if self.conf['identity'] == 'fqdn':
            self.info['host'] = task_vars.get('inventory_hostname', None);
        elif self.conf['identity'] == 'short':
            self.info['host'] = task_vars.get('inventory_hostname_short', None);
        else:
            self.info['host'] = task_vars.get('inventory_hostname_short', None);
            self.errors.append('"identity" task argument contains invalid value: "' + str(self.conf['identity']) + '"');

        '''
        Validate host name.
        '''
        rgx_rfc_1123 = '^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
        if not re.match(rgx_rfc_1123, self.info['host']):
            raise AnsibleError("the '" + self.info['host'] +  "' hostname does not comply with RFC1123");


        self.conf['play_uuid'] = self._task.args.get('play_uuid', str(uuid.uuid1()));
        self.conf['task_uuid'] = self._task.args.get('task_uuid', str(uuid.uuid1()));

        '''
        Define output directory.
        '''
        self.refs['h'] = self.info['host'];
        self.refs['P'] = self.conf['play_uuid'];
        self.refs['p'] = self.conf['task_uuid'];
        self.info['fqdn'] = task_vars.get('inventory_hostname', None);
        if self.info['fqdn']:
            self.refs['F'] = self.info['fqdn'];
        else:
            self.refs['F'] = '';

        self.conf['output_dir'] = self._task.args.get('output_dir', None);
        if self.conf['output_dir'] is None:
            self.conf['output_dir'] = self._task.args.get('output', None);
        if self.conf['output_dir'] is not None:
            self.conf['output_dir'] = self._decode_ref(self.conf['output_dir']);

        '''
        Create a temporary directory for command-line output.
        '''
        try:
            (head, tail) = os.path.split(C.DEFAULT_LOCAL_TMP)
            self.conf['temp_dir'] = os.path.join(head, self.plugin_name, self.conf['play_uuid'], self.conf['task_uuid'], self.info['host']);
        except:
            self.conf['temp_dir'] = os.path.join(os.getenv("HOME"), '.ansible', 'tmp', self.plugin_name, self.conf['play_uuid'], self.conf['task_uuid'], self.info['host']);
        try:
            os.makedirs(self.conf['temp_dir']);
        except OSError as exception:
            if exception.errno != errno.EEXIST:
                raise AnsibleError('[ERROR] failed to create temporary directory: ' + traceback.format_exc());

        '''
        TODO: does not apply
        The following two variables instruct the plugin to store output of the
        running configuration of a device in a file called "configuration", and
        its version information in a file called "version." This provides uniformity
        when it comes to storing the above information. Regardless which cli command
        was used to retrieve running configuration of a device, it could be always
        found in "configuration" file.
        '''

        '''
        The `on_error` and `on_prompt` instruct the plugin what to do when
        encountering an error or being prompted for Yes/No response.
        The two valid values are `abort` and `continue`.
        '''
        for i in ['prompt', 'error']:
            self.conf['on_' + i] = self._task.args.get('on_' + i, 'abort');
            if self.conf['on_' + i] not in ['abort', 'continue']:
                self.errors.append('the \'' + str(self.conf['on_' + i]) + '\' is not a valid option for \'' + self.plugin_name + '\' plugin');
                return dict(msg='\n'.join(self.errors), log_dir=self.conf['temp_dir'], failed=True);

        self.conf['disable_defaults'] = boolean(self._task.args.get('disable_defaults', 'no'));
        self.conf['no_host_key_check'] = boolean(self._task.args.get('no_host_key_check', 'no'));
        self.conf['allowed_sections'] = self._task.args.get('sections', None);
        if self.conf['allowed_sections'] is not None:
            self.conf['allowed_sections'] = [s.strip() for s in self.conf['allowed_sections'].split(",")]
            if self.conf['allowed_sections']:
                self.conf['allowed_sections'].extend(['conf', 'configuration', 'version']);
        self.refs['h'] = self.info['host'];
        self.refs['P'] = self.conf['play_uuid'];
        self.refs['p'] = self.conf['task_uuid'];
        self.info['fqdn'] = task_vars.get('inventory_hostname', None);
        self.refs['F'] = self.info['fqdn']; 
        self.info['hostname'] = task_vars.get('inventory_hostname_short', None);
        for i in ['os', 'host_overwrite', 'host_port', 'host_protocol', 'jumphosts', 'timeout']:
            self.info[i] = task_vars.get(self.plugin_name + '_' + i, None);
            if self.info[i] is None:
                self.info[i] = task_vars.get(i, None);
            if self.info[i] is None and i in ['os']:
                self.errors.append('\'' + self.plugin_name + '_' + i + '\' inventory attribute must be associated with ' + self.info['host']);
                return dict(msg='\n'.join(self.errors), log_dir=self.conf['temp_dir'], failed=True);

        '''
        Determine the interface to interract with a remote system.
        Currently, there are two types: shell and api
        '''
        api_interfaces = [
            'rest',
        ];
        if self.info['os'] in api_interfaces:
            self._is_api_driven = True;
        else:
            self._is_api_driven = False;

        if self._is_api_driven:
            for i in ['api_endpoint']:
                v = task_vars.get(i, None);
                if v is None:
                    self.errors.append('interraction with API-driven operating systems requires defining ' + i + ' ' + self.info['host']);
                    return dict(msg='\n'.join(self.errors), log_dir=self.conf['temp_dir'], failed=True);
                self.info[i] = v;

        '''
        Set default session timeout.
        '''

        if self.info['timeout'] is None:
            self.info['timeout'] = '30';

        '''
        Indicate whether stdin is a terminal.
        '''
        if not sys.stdin.isatty():
            ''' stdin is connected to a tty device. '''
            self.conf['tty'] = '1';
        else:
            self.conf['tty'] = '0';

        '''
        Load plugin's configuration file and it exceptions.
        '''

        self._load_conf();
        self.conf['cliset_exc'] = self._task.args.get('cliset_exc', os.path.join(self.ansible_root, 'files', self.plugin_name, 'exceptions.yml'));
        self._load_exceptions();

        '''
        Check for operating system support.
        '''

        if 'allowed_os' not in self.conf:
            raise AnsibleError("operating system filter was not found.");
        if not isinstance(self.conf['allowed_os'], list):
            raise AnsibleError("operating system filter is invalid.");

        for _os in self.conf['allowed_os']:
            if 'name' not in _os:
                raise AnsibleError("operating system filter entry must have 'name' attribute.");
            if _os['name'] == self.info['os']:
                if 'exit_sequence' in _os:
                    self.conf['exit_sequence'] = _os['exit_sequence'];
                else:
                    self.conf['exit_sequence'] = ['exit'];
                if 'disable_paging' in _os:
                    self.status['paging_mode'] = 'enabled';
                    self.conf['paging'] = _os['disable_paging'];
                if 'set_prompt' in _os:
                    self.status['prompt_mode'] = 'enabled';
                    self.conf['prompt'] = _os['set_prompt'];
                if 'facts' in _os:
                    self.conf['fact_patterns'] = _os['facts'];
                break;

        if 'exit_sequence' not in self.conf:
            self.errors.append('the ' + self.info['os'] + ' operating system is unsupported');
            return dict(msg='\n'.join(self.errors), log_dir=self.conf['temp_dir'], failed=True);

        '''
        os_cliset_dir parameter is optional. it points to the directory containing references
        to cli commands to run on a particular operating system or device. The directory
        path defaults to ansible files/ndmtk directory inside ansible inventory directory.
        '''

        self.conf['cliset_os_default_dir'] = os.path.join(self.plugin_root, 'files/cli/os');
        self.conf['cliset_os_dir'] = self._task.args.get('cliset_os_dir', os.path.join(self.ansible_root, 'files', self.plugin_name, 'os'));
        self.conf['cliset_host_dir'] = self._task.args.get('cliset_host_dir', os.path.join(self.ansible_root, 'files', self.plugin_name, 'host'));
        self.conf['cliset_core_dir'] = self._task.args.get('cliset_core_dir', os.path.join(self.plugin_root, 'files/cli/core'));
        if not self.conf['disable_defaults']:
            for i in ['os_default', 'os', 'host']:
                if i in ['os_default']:
                    filename = self.info['os'] + '.yml';
                else:
                    filename = self.info[i] + '.yml';
                self.conf['cliset_' + i] = os.path.join(self.conf['cliset_' + i + '_dir'], filename);
                self._load_cliset(self.conf['cliset_' + i], i);
            if self._is_dir_exists(self.conf['cliset_core_dir']):
                for dp, dns, dfs in os.walk(self.conf['cliset_core_dir']):
                    for fn in dfs:
                        fp = os.path.join(dp, fn);
                        if self._load_cliset(fp, 'core') == False:
                            raise AnsibleError("data set of core cli commands failed to load: " + str(fp) + '\n' + '\n'.join(self.errors));
        else:
            self.conf['cliset_os_default'] = os.path.join(self.conf['cliset_os_default_dir'], self.info['os'] + '.yml');
            self._load_cliset(self.conf['cliset_os_default'], 'os_default', commit=False);
            self.conf['cliset_spec'] = self._task.args.get('cliset_spec', None);
            if self.conf['cliset_spec']:
                if re.match(r'/', self.conf['cliset_spec']):
                    self._load_cliset(self.conf['cliset_spec'], 'spec');
                else:
                    self._load_cliset(os.path.join(self.ansible_root, self.conf['cliset_spec']), 'spec');

        if self.errors:
            return dict(msg='\n'.join(self.errors), log_dir=self.conf['temp_dir'], failed=True);

        self.conf['timestamp'] = datetime.datetime.now().strftime(".%H%M%S");
        self.file_prefix = self.info['host'] + '.';
        for i in ['log', 'stdout', 'exp', 'dbg', 'log_connect', 'log_disconnect']:
            self.conf[i] = os.path.join(self.conf['temp_dir'], self.file_prefix + i);
        if self._play_context.check_mode:
            display.vvv('running in check mode', host=self.info['host']);
        display.vvv('plugin name: ' + self.plugin_j2, host=self.info['host']);
        display.vvv('plugin temp dir: ' + self.conf['temp_dir'], host=self.info['host']);
        display.vvv('temporary log file: ' + self.conf['log'], host=self.info['host']);
        display.v('temporary log directory: ' + self.conf['temp_dir'], host=self.info['host']);

        '''
        Next, the plugin load the list of user credentials to access the host associated with the task.
        '''

        credentials = self._task.args.get('credentials', None); 
        if not credentials:
            if self._play_context.check_mode:
                for c in ['username', 'password', 'password_enable']:
                    self.conf[c] = 'check_mode';
            else:
                raise AnsibleError(self.plugin_name + ' failed to locate access credentials for remote devices');
        else:
            self.keystore = self._load_credentials(credentials);
            if self.errors:
                return dict(msg='\n'.join(self.errors), log_dir=self.conf['temp_dir'], failed=True);
            j = 0;
            for c in self.keystore:
                for k in c:
                    if k not in ['password', 'password_enable', 'api_auth_value']:
                        display.vvv('credentials (' + str(j)  + '): ' + str(k) + ': ' + str(c[k]), host=self.info['host']);
                j += 1;

        '''
        Create network connection string via either ssh or telnet.
        '''

        self._get_network_connectivity_details();

        display.vvv('host information:\n' + json.dumps(self.info, indent=4, sort_keys=True), host=self.info['host']);
        display.vvv('plugin configuration:\n' + json.dumps(self.conf, indent=4, sort_keys=True), host=self.info['host']);

        display.vv('keystore:\n' + pprint.pformat(self.keystore), host=self.info['host']);
        display.vv('activekey:\n' + pprint.pformat(self.activekey), host=self.info['host']);

        '''
        Check whether there is a valid password in the active credentials set.
        '''
        _keystore_item, _keystore_error = self._get_item_from_key('password', check_mode=True);
        if _keystore_error:
            if _keystore_error in ['PIN_NOT_FOUND', 'TOKEN_NOT_FOUND', 'TOKEN_FILE_NOT_FOUND'] or re.match('NO_', _keystore_error):
                raise AnsibleError(_keystore_error);

        if self.errors or self.conf['cliset_last_id'] == 0:
            '''
            Triggered when any of the previous steps produced an error ir cli set is empty.
            '''
            self.status['return_code'] = 1;
            self.status['return_status'] = 'failed';
            self.status['skipped'] = 'yes';
            if not self.errors:
                self.status['return_msg'] = 'no cli commands found';
        else:
            '''
            Connect to a remote device.
            '''
            self._remote_play();

        '''
        TODO: validate that `_remote_play()` sets `return_code` and `return_status` in `self.status`!
              including `unreachable` status
        '''

        if 'return_msg' not in self.status:
            self.status['return_msg'] = '';
        if self.errors:
            self.status['return_errors'] = list(self.errors);
        if self.status['return_status'] == 'unreachable':
            result = dict(msg=self.status['return_msg'], unreachable=True);
        elif self.status['return_status'] == 'failed':
            result = dict(msg=self.status['return_msg'], failed=True);
        else:
            _failed_cli = [];
            for _id in self.conf['cliset']:
                if 'status' in self.conf['cliset'][_id]:
                    if self.conf['cliset'][_id]['status'] == 'failed':
                        _failed_cli.append(self.conf['cliset'][_id]['cli']);
            result = dict({});
            if _failed_cli:
                result['msg'] = 'failed \'' + '\' ,\''.join(_failed_cli) + '\'';
                result['failed'] = True;
            else:
                if 'changed' in self.info:
                    result['changed'] = True;
                result['ok'] = True;

        self._commit();
        self.conf['time_end'] = int(round(time.time() * 1000));
        #display.vvv('plugin configuration:\n' + json.dumps(self.conf, indent=4, sort_keys=True), host=self.info['host']);
        self._report();
        if 'junit' in self.conf:
            if self._is_file_exists(self.conf['junit']):
                result['junit'] = self.conf['junit'];

        for i in ['data', 'temp']:
            if i + '_dir' in self.conf:
                if self._is_dir_exists(self.conf[i + '_dir']):
                    if not self._is_dir_empty(self.conf[i + '_dir']):
                        result[i + '_dir'] = self.conf[i + '_dir'];
        self._cleanup();
        if len(self.errors) > 0 and 'ok' in result:
            if result['ok'] == True:
                display.display('<' + self.info['host'] + '> encountered the following issues:', color='yellow');
                for e in self.errors:
                    display.display('<' + self.info['host'] + '> ' + str(e), color='yellow');
        return result;


    def _cleanup(self):
        for d in ['temp_dir']:
            if d in self.conf:
                if self._is_dir_exists(self.conf[d]):
                    if not self._is_dir_empty(self.conf[d]):
                        for dirpath, dirnames, files in os.walk(os.path.expanduser(self.conf[d])):
                            for fn in files:
                                fp = os.path.join(dirpath, fn);
                                if self._is_file_exists(fp):
                                    if self._is_file_empty(fp):
                                        try:
                                            os.remove(fp);
                                            display.vvv('deleted empty file: ' + fp);
                                        except:
                                            display.vvv('failed to delete empty file: ' + fp);
        return;


    def _get_item_from_key(self, item, check_mode=False):
        attempts = 0;
        token_wait_time = 6;
        if item in self.activekey:
            value = str(self.activekey[item]);
            if value == 'pin,token':
                if not check_mode:
                    display.display('<' + self.info['host'] + '> requires One-Time-Password (OTP)', color='green');
                while True:
                    if 'pin' not in self.activekey:
                        return None, "PIN_NOT_FOUND";
                    if 'token' not in self.activekey:
                        return None, "TOKEN_NOT_FOUND";
                    token = None;
                    try:
                        with open(os.path.expanduser(self.activekey['token']),'r') as f:
                            token = f.readlines();
                    except:
                        return None, "TOKEN_FILE_NOT_FOUND";
                    if token is None:
                        return None, "TOKEN_FILE_NOT_FOUND";
                    if len(token) > 0:
                        ts_now = int(time.time());
                        m = re.match(r"(?P<ts>\d+);(?P<token>\d+);(?P<lifetime>\d+)", token[0].strip());
                        if m:
                            token = m.groupdict()['token'];
                            ts_now = int(time.time());
                            ts_token = int(m.groupdict()['ts']) + int(m.groupdict()['lifetime']);
                            if ts_now > ts_token:
                                if check_mode:
                                    return self.activekey['pin'] + token, None;
                                if attempts > 5:
                                    return None, "TOKEN_EXPIRED";
                                attempts += 1;
                                display.display('<' + self.info['host'] + '> token expired in "' + self.activekey['token'] + '", sleep for ' + str(token_wait_time) + ' seconds', color='yellow');
                                time.sleep(token_wait_time);
                                continue;
                            display.display('<' + self.info['host'] + '> using token: ' + token + ', lifetime: ' + str(ts_token - ts_now) + ' seconds', color='green');
                            return self.activekey['pin'] + token, None;
                        else:
                            return None, "TOKEN_INVALID_FORMAT";
                    else:
                        return None, "TOKEN_NOT_FOUND";
            return value, None;
        else:
            return None, "NO_" + item.upper();

    def _get_key_from_keystore(self, host):
        '''
        TODO: request fingerprints for jumphosts.
        '''
        if len(self.keystore) > 0:
            self.activekey = self.keystore.pop(0);
            return None;
        return 'no more access credentials left to try';

    def _get_network_connectivity_details(self):
        '''
        Create network connection string via either ssh or telnet.

        The `host_protocol` argument can have multiple possible options:
        - `ssh`: instructs the plugin to use available ssh utility
        - `telnet`: instructs the plugin to use available telnet utility
        - `serial`: instructs the plugin to use available serial console utility,
          e.g. `screen`, `tip`, `minicom`, etc.
        '''

        self.conf['args'] = [];
        
        '''
        Initially, the plugin decides on how to deal with the actual device
        it is accessing. By default, the plugin accesses devices via SSH
        protocol. Later, the plugin will add jumphost information, if necessary.
        '''

        err = self._get_key_from_keystore(self.info['host']);
        if err:
            self.errors.append(err);
            return;

        _proto = 'ssh';
        if self.info['host_protocol'] is not None:
            '''
            TODO: add support for serial console communications.
            '''
            if self.info['host_protocol'] not in ['ssh', 'telnet']:
                self.errors.append("the '" + self.plugin_name + "' action does not support network connectivity with " + str(self.info['host_protocol']) + ".");
                return;
            _proto = self.info['host_protocol'];
            self.conf['args'].append(self.info['host_protocol']);
        else:
            self.conf['args'].append('ssh');

        if _proto == 'ssh':
            if self.conf['no_host_key_check']:
                self.conf['args'].extend(['-o', 'UserKnownHostsFile=/dev/null']);
                self.conf['args'].extend(['-o', 'StrictHostKeyChecking=no']);
            if self.info['host_port'] is not None:
                self.conf['args'].extend(['-p', str(self.info['host_port'])]);
            self.conf['args'].append('-tt');
            _ssh_user = self.activekey['username'];
            _ssh_host = self.info['fqdn'];
            if self.info['host_overwrite'] is not None:
                _ssh_host = self.info['host_overwrite']
            self.conf['args'].append(_ssh_user + "@" + _ssh_host);
        elif _proto == 'telnet':
            if self.info['host_overwrite'] is not None:
                self.conf['args'].append(self.info['host_overwrite']);
            else:
                self.conf['args'].append(self.info['host']);
            if self.info['host_port'] is not None:
                self.conf['args'].append(str(self.info['host_port']));
        else:
            pass;
            

        '''
        TODO: add support for jumphosts

        The `jumphosts` attribute of an inventory host contains the path
        the plugin must follow in order to reach the actual device.
        The `jumphosts` attribute is a string. the delimeter is "," (comma).
        The access credentials to a jump host must be in the vault
        with the rest of access credentials.
        '''

        if 'jumphosts' in self.info:
            pass;

        return;


    def _remote_play(self):
        '''
        This function is a wrapper for ssh and telnet commands via expect.
        '''

        '''
        Build expect template to handle interraction with a remote device.
        '''

        j2env = jinja2.Environment(loader=jinja2.FileSystemLoader(self.plugin_root));
        j2tmpl = j2env.get_template(self.plugin_name + '.j2');
        j2conf = {
            'host': self.info['host'],
            'operating_system': self.info['os'],
            'controller': 'master',
            'plugin': self.plugin_name,
            'task_uuid': self.conf['task_uuid'],
            'connection_string': ' '.join(self.conf['args']),
            'stdout_file_name': self.conf['stdout'],
            'log_dir': self.conf['temp_dir'],
            'log_file_name': self.conf['log'],
            'dbg_file_name': self.conf['dbg'],
            'log_connect_file_name': self.conf['log_connect'],
            'log_disconnect_file_name': self.conf['log_disconnect'],
            'on_prompt': self.conf['on_prompt'],
            'session_timeout': self.info['timeout'],
            'is_tty': self.conf['tty'],
        };
        j2rc = {
            0:  {'msg': 'ok', 'status': 'ok'},
            1:  {'msg': 'review error log for details', 'status': 'failed'},
            64: {'msg': 'connection timeout', 'status': 'unreachable'},
            65: {'msg': 'connection failed', 'status': 'unreachable'},
            66: {'msg': 'dns resolution failed', 'status': 'unreachable'},
            67: {'msg': 'authentication failed', 'status': 'failed'},
            68: {'msg': 'hostname detection failed', 'status': 'failed'},
            69: {'msg': 'prompt detection failed', 'status': 'failed'},
            70: {'msg': 'disabling paging failed', 'status': 'failed'},
            71: {'msg': 'remote session controller failed to receive credentials from ansible', 'status': 'failed'},
            72: {'msg': 'enabling automation mode failed', 'status': 'failed'},
            73: {'msg': 'no spawned process found when terminating session', 'status': 'failed'},
            74: {'msg': 'received unknown ssh fingerprint', 'status': 'failed'},
            75: {'msg': 'remote session controller failed to receive cli instructions from ansible', 'status': 'failed'},
            76: {'msg': 'remote session controller failed to communicate its status', 'status': 'failed'},
            77: {'msg': 'setting custom prompt failed', 'status': 'failed'},
            78: {'msg': 'enabling scripting mode failed', 'status': 'failed'},
            79: {'msg': 'no matching ssh key exchange method was found', 'status': 'failed'},
            98: {'msg': 'local session controller failed passing expect instructions via the stdin of the remote controller', 'status': 'failed'},
            99: {'msg': 'local session controller interrupted communication with the remote controller', 'status': 'failed'},
        };

        for i in ['paging', 'scripting', 'prompt']:
            '''
            Initially, the mode is set to `enabled`, Then, it is changed to
            either `ok` or `failed`.
            '''
            self.status[i + '_mode'] = 'enabled';
            if i in self.conf:
                self.status[i + '_mode'] = 'enabled';
            else:
                self.status[i + '_mode'] = 'disabled';

        j2exp = j2tmpl.render(j2conf);
        try:
            os.chmod(self.conf['temp_dir'], stat.S_IRWXU);
            for i in ['log', 'log_connect', 'log_disconnect', 'stdout', 'exp', 'dbg']:
                with open(self.conf[i], 'a') as fh:
                    os.utime(fh.name, None);
                    os.chmod(fh.name, stat.S_IRUSR | stat.S_IWUSR);
        except:
            self.errors.append('an attempt by ' + self.plugin_name + ' plugin to secure temporary directory \'' + self.conf['temp_dir'] + '\' failed.');
            exc_type, exc_value, exc_traceback = sys.exc_info();
            self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
            return;

        if self.conf['show_expect'] == True:
            with open(self.conf['exp'], 'a') as fh_exp:
                fh_exp.write(j2exp);

        try:
            '''
            Create pipes for IPC:
              * pr - Parent Read
              * pw - Parent Write
              * cr - Child Read
              * cw - Child Write
            '''
            remote_session_stdin_pr, remote_session_stdout_cw = os.pipe();
            remote_session_stdin_cr, remote_session_stdout_pw = os.pipe();
        except:
            self.errors.append('an attempt by ' + self.plugin_name + ' plugin to create a Pipe for the purpose of communicating to a child process script failed.');
            exc_type, exc_value, exc_traceback = sys.exc_info();
            self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
            return;

        try:
            remote_session_pid = os.fork();
            if remote_session_pid != 0:
                ''' the following code is processed by parent process '''
                try:
                    os.close(remote_session_stdin_cr);
                    os.close(remote_session_stdout_cw);
                except:
                    self.errors.append('an attempt by ' + self.plugin_name + ' plugin to close unnecessary endpoints in parent process failed.');
                    exc_type, exc_value, exc_traceback = sys.exc_info();
                    self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));

                '''
                Parent kept `remote_session_stdin_pr` for read-only and `remote_session_stdout_pw` for write-only.
                '''
                remote_session_stdout_pw = os.fdopen(remote_session_stdout_pw, 'w');
                '''
                Importantly, `remote_session_stdout_pw` is of type `file`, while `remote_session_stdin_pr` is of type `int`.
                This means that `remote_session_stdin_pr` is closed with `remote_session_stdin_pr.close()`,
                while `remote_session_stdout_pw` is closed differently is closed with
                `remote_session_stdout_pw.flush()` and `remote_session_stdout_pw.close()`
                '''
                display.vvv('remote_session_pid: "' + str(remote_session_pid) + '"', host=self.info['host']);
            else:
                ''' the following code is processed by child process '''
                try:
                    os.close(remote_session_stdin_pr);
                    os.close(remote_session_stdout_pw);
                except:
                    self.errors.append('an attempt by ' + self.plugin_name + ' plugin to close unnecessary endpoints in child process failed.');
                    exc_type, exc_value, exc_traceback = sys.exc_info();
                    self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
                '''
                First, the child keeps `remote_session_stdin_cr` for read-only and `remote_session_stdout_cw` for write-only.
                '''
                try:
                    os.dup2(remote_session_stdin_cr, 0);
                    os.dup2(remote_session_stdout_cw, 1);
                    os.dup2(remote_session_stdout_cw, 2);
                except:
                    self.errors.append('an attempt by ' + self.plugin_name + ' plugin to send child\'s STDIN to parent\'s STDOUT failed.');
                    exc_type, exc_value, exc_traceback = sys.exc_info();
                    self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));

                '''
                Second, the child makes the following file descriptor duplicates. Essentially, the child disconnects
                its end of the pipe and plugs it to file descriptors `0`, `1`, `2`.
                Thus, `remote_session_stdin_cr` (read-only) receives:
                - `0`: standard input 
                The `remote_session_stdout_cw` (write-only) writes to:
                - standard output (`1`) of the parent/manager
                - standard error (`2`) of the parent/manager
                '''
                if self._play_context.check_mode:
                    os.execvp('expect', ['expect', '-v']);
                else:
                    if self.conf['show_expect'] == True:
                        '''
                        If `show_expect=yes` is set, expect script is left on a file system.
                        Otherwise, it is passed via stdin.
                        '''
                        os.execvp('expect', ['expect', '-f', self.conf['exp']]);
                    else:
                        os.execvp('expect', ['expect', '-f', '-']);
        except:
            self.errors.append('an attempt by ' + self.plugin_name + ' plugin to create a child process for its expect script failed.');
            exc_type, exc_value, exc_traceback = sys.exc_info();
            self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
            return;

        if remote_session_pid != 0:
            '''
            This is parent process space.
            '''
            _is_clean_exit = False;
            try:
                _break = False;
                _is_clean_start = False;
                if self.conf['show_expect'] != True:
                    '''
                    Here, the plugin passes expect script via standard input.
                    '''
                    try:
                        os.write(remote_session_stdout_pw.fileno(), j2exp + '\n' + '\x03');
                        _is_clean_start = True;
                    except:
                        self.status['return_code'] = 98;
                        display.vvv('failed to pass expect instructions via stdin', host=self.info['host']);
                        self.errors.append('an attempt by ' + self.plugin_name + ' plugin to pass expect instructions via stdin failed');
                        exc_type, exc_value, exc_traceback = sys.exc_info();
                        self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
                else:
                    _is_clean_start = True;
                while True:
                    if not _is_clean_start:
                        break
                    '''
                    This variable holds RX buffer of the parent and TX buffer of the child.
                    '''
                    remote_session_stdin = '';
                    while True:
                        try:
                            '''
                            Parent process reads from child process writes, i.e. expect stdout.
                            '''
                            inc = os.read(remote_session_stdin_pr, 1);
                            if inc == '':
                                '''
                                The `os.read()` function returns an empty string when file
                                descriptor is closed, i.e. when the end of the file referred
                                to by it has been reached.
                                '''
                                _is_clean_exit = True;
                                self.status['disconnect_end'] = int(round(time.time() * 1000));
                                _break = True;
                                break;
                            elif inc == '\n':
                                '''
                                The child sends new line character, i.e. request is ready for pickup.
                                '''
                                break;
                            else:
                                '''
                                Filter data coming into stdin of the parent.
                                '''
                                if ord(inc) < 32 and ord(inc) not in [10]:
                                    display.display('<' + self.info['host'] + '> bad character ' + str(ord(inc)) + ' while at "' + _lst_cli['cli'] + '" command', color='yellow');
                                    continue;
                                if ord(inc) > 126:
                                    display.display('<' + self.info['host'] + '> bad character ' + str(ord(inc)) + ' while at "' + _lst_cli['cli'] + '" command', color='yellow');
                                    continue;
                                '''
                                If the received char is supported, then add it to the buffer.
                                Else, display an issue.
                                '''
                                remote_session_stdin += inc;
                        except:
                            _break = True;
                            break;
                    _prompted = False;
                    for prompt in ['username', 'password', 'password_enable']:
                        if re.search(prompt + ':', remote_session_stdin):
                            _prompted = True;
                            display.vvv('detected "' + prompt + '" prompt, sending response', host=self.info['host']);
                            _prompt_response, response_error = self._get_item_from_key(prompt);
                            if response_error:
                                self.errors.append('received ' + response_error + ' when looking up ' + prompt);
                                os.write(remote_session_stdout_pw.fileno(), 'INTERNAL_ERROR' + "\n");
                            else:
                                os.write(remote_session_stdout_pw.fileno(), _prompt_response + "\n");
                    if not _prompted:
                        if str(remote_session_stdin) == "":
                            pass;
                        elif re.search('status:', remote_session_stdin):
                            display.vvv('detected status message: "' + str(remote_session_stdin) + '"', host=self.info['host']);
                            '''
                            The forked process may send "status:connected:yes", or "status:connnected:no"
                            '''
                            remote_status = str(remote_session_stdin).split(":");
                            if len(remote_status) > 2:
                                self.status[remote_status[1]] = remote_status[2];
                                if remote_status[1] in ['paging_mode', 'scripting_mode', 'prompt_mode']:
                                    if remote_status[2] != 'configured':
                                        self.conf['abort'] = True;
                                        if remote_status[1] == "prompt_mode":
                                            self.status['return_code'] = 77;
                                        elif remote_status[1] == "scripting_mode":
                                            self.status['return_code'] = 78;
                                        elif remote_status[1] == "paging_mode":
                                            self.status['return_code'] = 70;
                                        else:
                                            pass;
                                elif remote_status[1] == 'spawned':
                                    self.status['connect_start'] = int(round(time.time() * 1000));
                                elif remote_status[1] == 'disconnected':
                                    self.status['disconnect_start'] = int(round(time.time() * 1000));
                                elif remote_status[1] == 'authorized':
                                    self.status['connect_end'] = int(round(time.time() * 1000));
                                else:
                                    pass;
                            try:
                                os.write(remote_session_stdout_pw.fileno(), "ok\n");
                            except:
                                display.vvv('sent failed for respond to status report: ' + remote_status, host=self.info['host']);
                                self.errors.append('an attempt by ' + self.plugin_name + ' plugin to respond to status report: ' + remote_status);
                                exc_type, exc_value, exc_traceback = sys.exc_info();
                                self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
                                break;
                        elif re.search('clitask:', remote_session_stdin):
                            _prompted = True;
                            '''
                            if the plugin previously sent a command to a remote device,
                            check the result of the command's execution by looking at the
                            command's output.

                            The `cliset_last_eid` variable is incremented by `_get_cli_task()` function
                            '''
                            _lst_eid = self.conf['cliset_last_eid'];
                            if _lst_eid > 0 and _lst_eid in self.conf['cliset']:
                                _lst_cli = copy.deepcopy(self.conf['cliset'][_lst_eid]);
                                _fp = os.path.join(self.conf['temp_dir'], _lst_cli['filename']);
                                if _lst_cli['status'] == 'skipped':
                                    display.display('<' + self.info['host'] + '> skipped "' + _lst_cli['cli'] + '" command: skip', color='yellow');
                                else:
                                    _is_failed = self._parse_cli_output(_fp, _lst_eid);
                                    '''
                                    It makes sense to refresh this dictionary every time there is an external function.
                                    '''
                                    _lst_eid = self.conf['cliset_last_eid'];
                                    _lst_cli = copy.deepcopy(self.conf['cliset'][_lst_eid]);
                                    _task_description = '';
                                    if 'description' in self.conf['cliset'][_lst_eid]:
                                        _task_description = '<' + self.info['host'] + '> ' + _lst_cli['description'] + '\n';
                                    if _is_failed:
                                        if _lst_cli['status'] == 'retry':
                                            if 'retries' not in _lst_cli:
                                                self.conf['cliset'][_lst_eid]['retries'] = 0;
                                            else:
                                                if _lst_cli['retries'] > 3:
                                                    self.conf['cliset'][_lst_eid]['status'] = 'failed';
                                                else:
                                                    self.conf['cliset'][_lst_eid]['retries'] += 1;
                                                    display.display(_task_description + '<' + self.info['host'] + '> the \'' + _lst_cli['cli'] + \
                                                            '\' command: queued for re-execution', color='yellow');
                                        elif _lst_cli['status'] == 'sudo_eligible':
                                            display.display(_task_description + '<' + self.info['host'] + '> the \'' + _lst_cli['cli'] + \
                                                    '\' command: queued for re-execution with escalated privileges', color='yellow');
                                        else:
                                            self.conf['cliset'][_lst_eid]['status'] = 'failed';
                                            if self.conf['on_error'] == 'abort':
                                                ''' stop execution and send abort '''
                                                self.conf['abort'] = True;
                                                '''
                                                TODO: disable _break
                                                '''
                                                #_break = True;
                                        if self.conf['cliset'][_lst_eid]['status'] == 'failed':
                                            display.display(_task_description + '<' + self.info['host'] + '> completed running \'' + \
                                                    _lst_cli['cli'] + '\' command: fail', color='red');
                                    else:
                                        self.conf['cliset'][_lst_eid]['status'] = 'ok';
                                        display.display(_task_description + '<' + self.info['host'] + '> completed running \'' + _lst_cli['cli'] + '\' command: ok', color='green');
                                        self._lookup_additional_commands(_fp, _lst_eid);
                                        if 'tags' in self.conf['cliset'][_lst_eid]:
                                            if 'version' in self.conf['cliset'][_lst_eid]['tags']:
                                                self._lookup_host_facts(_fp, _lst_eid);
                                                if self.conf['cliset'][_lst_eid]['status'] == 'failed':
                                                    self.conf['abort'] = True;
                                                else:
                                                    ''' The lookup for host facts was successful. '''
                                                    display.vv('<' + self.info['host'] + '> the lookup for host facts after "' + str(self.conf['cliset'][_lst_eid]['cli']) +  '" was successful');
                                                    if self._evaluate_conditions(_lst_eid) is not None:
                                                        self.conf['cliset'][_lst_eid]['status'] = 'failed';
                                                        self.conf['abort'] = True;
                                        if _lst_cli['mode'] == 'analytics':
                                            self.conf['cliset'][_lst_eid]['sha1'] = self._get_sha1_hash(_fp);
                                            self.conf['cliset'][_lst_eid]['path'] = _fp;
                            '''
                            check for the commands pending execution on a remote device.
                            '''
                            clitask, nonl = self._get_cli_task('task');
                            display.vvv('prompted for cli task, sending: ' + clitask, host=self.info['host']);
                            try:
                                if nonl:
                                    os.write(remote_session_stdout_pw.fileno(), clitask);
                                else:
                                    os.write(remote_session_stdout_pw.fileno(), clitask + "\n");
                            except:
                                display.vvv('sent failed for: ' + str(clitask).rstrip(), host=self.info['host']);
                                self.errors.append('an attempt by ' + self.plugin_name + ' plugin to communicate with the remote hosts with pipes failed');
                                exc_type, exc_value, exc_traceback = sys.exc_info();
                                self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
                                break;
                        elif re.search('clifile:', remote_session_stdin):
                            display.vvv('prompted for cli output filename', host=self.info['host']);
                            _prompted = True;
                            clifile, nonl = self._get_cli_task('file');
                            display.vvv('sending: ' + clifile, host=self.info['host']);
                            try:
                                os.write(remote_session_stdout_pw.fileno(), clifile + "\n");
                            except:
                                display.vvv('sent failed for: ' + clifile, host=self.info['host']);
                                self.errors.append('an attempt by ' + self.plugin_name + ' plugin to communicate with the remote hosts with pipes failed');
                                exc_type, exc_value, exc_traceback = sys.exc_info();
                                self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback)); 
                                break;
                        elif re.search('(climode|cliexit|clitimeout):', remote_session_stdin):
                            '''
                            A command may be for analytics purposes, e.g. `show ip route`, or it
                            may be a part of a deployment job. If it is a deployment job, any error
                            is a signal to abort the job.
                            '''
                            request = 'mode';
                            if re.search('cliexit', remote_session_stdin):
                                request = 'exit';
                            elif re.search('clitimeout', remote_session_stdin):
                                request = 'timeout';
                            else:
                                pass
                            display.vvv('prompted for cli ' + request, host=self.info['host']);
                            _prompted = True;
                            response, nonl = self._get_cli_task(request);
                            try:
                                display.vvv('sending: ' + str(response), host=self.info['host']);
                                if request == 'exit':
                                    os.write(remote_session_stdout_pw.fileno(), '\n'.join(response) + "\n");
                                else:
                                    os.write(remote_session_stdout_pw.fileno(), response + "\n");
                            except:
                                display.vvv('sent failed for cli ' + request + ': ' + str(response), host=self.info['host']);
                                self.errors.append('an attempt by ' + self.plugin_name + ' plugin to communicate response to ' + request + ' with the remote host with pipes failed');
                                exc_type, exc_value, exc_traceback = sys.exc_info();
                                self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
                                break;
                        elif re.search('trap:', remote_session_stdin):
                            display.v('detected trap signal: "' + str(remote_session_stdin) + '"', host=self.info['host']);
                            self.errors.append('the ' + self.plugin_name + ' plugin stoped communicating in response to "' + str(remote_session_stdin) + '"');
                            self.conf['abort'] = True;
                            break;
                        else:
                            display.vvv('received unsupported prompt: "' + str(remote_session_stdin) + '"', host=self.info['host']);
                            pass;
                    if _break:
                        break;
            except:
                '''
                At this point it is important to know whether parent process finished waiting
                for the child to complete, i.e. received empty character from its file
                descriptor. If it did not, then the pipe needs to be closed, see `remote_session_stdin_pr`.
                '''
                display.vvv('The plugin encountered an error while communicating with the host', host=self.info['host']);
                if not _is_clean_exit:
                    self.errors.append('task manager pid failed exited before its child.');
                    if 'return_code' not in self.status:
                        self.status['return_code'] = 99;
                exc_type, exc_value, exc_traceback = sys.exc_info();
                self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));

            '''
            Close file descriptors for IPC pipes.
            '''
            try:
                os.close(remote_session_stdin_pr);
                remote_session_stdout_pw.flush();
                remote_session_stdout_pw.close();
            except:
                self.errors.append('an attempt by ' + self.plugin_name + ' plugin to close IPC pipes failed.');
                exc_type, exc_value, exc_traceback = sys.exc_info();
                self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
            try:
                '''
                The below is only making sense when the pipe was properly closed.
                However, if something went wrong on the expect side, we need to
                handle it differently.
                '''
                remote_session_rst = os.waitpid(remote_session_pid, 0);
                remote_session_rc = remote_session_rst[1];
                remote_session_rc = remote_session_rc >> 8;
                display.vvv('child process exited with: ' + str(remote_session_rc) + ' (' + str(type(remote_session_rc)) + ')', host=self.info['host']);
                if 'return_code' not in self.status:
                    self.status['return_code'] = remote_session_rc;
                else:
                    if self.status['return_code'] == 0:
                        self.status['return_code'] = remote_session_rc;
                if remote_session_rc > 1 and remote_session_rc < 64:
                    self.errors.append('child process exited with unsupported RC ' + str(remote_session_rc) + ' (' + str(type(remote_session_rc)) + ')');
                    self.status['return_code'] = 1;
            except:
                self.errors.append('an attempt by ' + self.plugin_name + ' plugin to communicate to its child process failed.');
                exc_type, exc_value, exc_traceback = sys.exc_info();
                self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
        '''
        TODO: should there be exit for child process?
        '''
        if 'return_code' in self.status:
            if self.status['return_code'] in j2rc:
                self.status['return_status'] = j2rc[self.status['return_code']]['status'];
                self.status['return_msg'] = j2rc[self.status['return_code']]['msg'];
        for i in ['return_code', 'return_status', 'return_msg']:
            if i in self.status:
                display.vv(i + ': ' + str(self.status[i]), host=self.info['host']);
            else:
                display.vv(i + ': ' + 'undefined', host=self.info['host']);
        return;


    def _get_cli_task(self, item):
        '''
        This function responds with the next task to execute, the task's associated
        filename, or the tasks' mode.
        '''

        _is_sudo_eligible = False;
        nonl = False;

        if item == 'exit':
            if 'exit_sequence' in self.conf:
                return self.conf['exit_sequence'], nonl;
            return 'exit', nonl;

        '''
        The `abort` variable could be used to tell the child process
        to exit, e.g. in response to SIGINT.

        TODO: incorporate `abort` in signal handling
        '''

        if self.conf['abort'] == True:
            return 'abort', nonl;

        for i in ['paging', 'scripting', 'prompt']:
            if item == 'timeout':
                break;
            if i + '_mode' not in self.status:
                continue;
            if self.status[i + '_mode'] != 'enabled':
                continue;
            if item == 'task':
                '''
                TODO: verify sequence of multiple exit commands works
                '''
                if isinstance(self.conf[i], list):
                    return '\n'.join(self.conf[i]), nonl;
                return self.conf[i], nonl;
            elif item in ['file', 'mode']:
                '''
                There is an existing connection log. The plugin will append
                the data to the log.
                '''
                return i, nonl;
            else:
                pass

        if 'cliset_last_eid' not in self.conf:
            return 'eol', nonl;
        if '_eof' in self.conf:
            return 'eol', nonl;
        if item == 'task':
            _break = False;
            '''
            Record time it took for the previous task to complete.
            '''
            if self.conf['cliset_last_eid'] in self.conf['cliset']:
                self.conf['cliset'][self.conf['cliset_last_eid']]['time_end'] = int(round(time.time() * 1000));

            while True:
                '''
                Re-execute commands requiring escalated privileges immediately. 
                '''
                if self.conf['cliset_last_eid'] in self.conf['cliset']:
                    if 'sudo_eligible' in self.conf['cliset'][self.conf['cliset_last_eid']]:
                        if self.conf['cliset'][self.conf['cliset_last_eid']]['sudo_eligible'] == 0:
                            self.conf['cliset'][self.conf['cliset_last_eid']]['sudo_eligible'] += 1;
                            _is_sudo_eligible = True;
                            break;

                '''
                TODO: simulate failure by looping indefinitelt and sleeping!

                The `cliset_last_eid` variable holding previously executed command
                identifier is incremented because it completed.
                '''
                self.conf['cliset_last_eid'] += 1;
                #display.display(str(self.conf['cliset'][self.conf['cliset_last_eid']]));
                '''
                This usually happens during retries, where status is either `conditional`, `retry`,
                `sudo_eligible`, or `unknown`.
                '''
                if self.conf['cliset_last_eid'] in self.conf['cliset']:
                    if self.conf['cliset'][self.conf['cliset_last_eid']]['status'] in ['ok', 'failed', 'skipped']:
                        continue;
                '''
                The plugin exits when the upper bound of the `cliset` is reached.
                '''
                if self.conf['cliset_last_eid'] not in self.conf['cliset']:
                    '''
                    The plugin will try to find commands that require retrial.
                    '''
                    i = 0;
                    while True:
                        i += 1;
                        if i in self.conf['cliset']:
                            if 'status' in self.conf['cliset'][i]:
                                if self.conf['cliset'][i]['status'] in ['retry', 'sudo_eligible']:
                                    self.conf['cliset_last_eid'] = i;
                                    break;
                        else:
                            self.conf['_eof'] = True;
                            return 'eol', nonl;
                    '''
                    At this point, the plugin knows the next available command to send.
                    '''

                '''
                Now, the plugin checks whether that next command has condition precedent
                and whether the condition is satisfied.
                '''
                if self.conf['cliset'][self.conf['cliset_last_eid']]['status'] == 'conditional':
                    '''
                    Check whether the condition precedent for the conditional command is satisfied.
                    If it is, then proceed with the execution.
                    '''
                    _is_conditions_match = True;
                    _is_met_conditions_precedent = True;
                    for x in ['conditions_match_all', 'conditions_match_all_nolimit', 'conditions_match_any']:
                        if x in self.conf['cliset'][self.conf['cliset_last_eid']]:
                            if not self._match_condition(x, self.conf['cliset'][self.conf['cliset_last_eid']][x]):
                                _is_conditions_match = False;
                                break;
                    for x in ['conditions_precedent_all']:
                        if x in self.conf['cliset'][self.conf['cliset_last_eid']]:
                            if 'facts' not in self.status:
                                display.vv('<' + self.info['host'] + '> no facts available for condition precedent analysis when polling for a task');
                                _is_met_conditions_precedent = False;
                                break;
                            if not self._conditions_precedent_is_met(x, self.status['facts'], self.conf['cliset'][self.conf['cliset_last_eid']][x]):
                                _is_met_conditions_precedent = False;
                                break;
                    if _is_conditions_match and _is_met_conditions_precedent:
                        self.conf['cliset'][self.conf['cliset_last_eid']]['status'] = 'unknown';
                        _break = True;
                        break;
                else:
                    _break = True
                if _break:
                    break;
        if self.conf['cliset_last_eid'] not in self.conf['cliset']:
            return 'eol', nonl;
        if item == 'task':
            '''
            Record a task's stat time.
            '''
            if self.conf['cliset_last_eid'] in self.conf['cliset']:
                self.conf['cliset'][self.conf['cliset_last_eid']]['time_start'] = int(round(time.time() * 1000));
                ts = time.strftime("%Y-%m-%dT%H:%M:%S UTC", time.gmtime(self.conf['cliset'][self.conf['cliset_last_eid']]['time_start'] / 1000));
                self.conf['cliset'][self.conf['cliset_last_eid']]['timestamp'] = ts;
            if 'no_newline' in self.conf['cliset'][self.conf['cliset_last_eid']]:
                if self.conf['cliset'][self.conf['cliset_last_eid']]['no_newline'] is True:
                    nonl = True;
            if _is_sudo_eligible:
                return 'sudo ' + self.conf['cliset'][self.conf['cliset_last_eid']]['cli'], nonl;
            return self.conf['cliset'][self.conf['cliset_last_eid']]['cli'], nonl;
        elif item == 'file':
            return self.conf['cliset'][self.conf['cliset_last_eid']]['filename'], nonl;
        elif item == 'timeout':
            if 'timeout' in self.conf['cliset'][self.conf['cliset_last_eid']]:
                return str(self.conf['cliset'][self.conf['cliset_last_eid']]['timeout']), nonl;
            else:
                return str(self.info['timeout']), nonl;
        elif item == 'mode':
            if 'append' in self.conf['cliset'][self.conf['cliset_last_eid']]:
                if self.conf['cliset'][self.conf['cliset_last_eid']]['append'] == True:
                    return self.conf['cliset'][self.conf['cliset_last_eid']]['mode'] + '-append', nonl;
            return self.conf['cliset'][self.conf['cliset_last_eid']]['mode'], nonl;
        else:
            pass;
        return 'eol', nonl;


    def _evaluate_conditions(self, cli_id):
        try:
            for i in self.conf['cliset']:
                if 'status' not in self.conf['cliset'][i]:
                    continue;
                if self.conf['cliset'][i]['status'] == 'conditional':
                    display.vv('<' + self.info['host'] + '> found conditional cli task: "' + str(self.conf['cliset'][i]['cli']) + '"');
                    _is_conditions_match = True;
                    _is_met_conditions_precedent = True;
                    for x in ['conditions_match_all', 'conditions_match_all_nolimit', 'conditions_match_any']:
                        if x in self.conf['cliset'][i]:
                            if not self._match_condition(x, self.conf['cliset'][i][x]):
                                _is_conditions_match = False;
                                break;
                    for x in ['conditions_precedent_all']:
                        if x in self.conf['cliset'][i]:
                            if 'facts' not in self.status:
                                display.vv('<' + self.info['host'] + '> no facts available for condition precedent analysis when parsing cli output from "' + str(self.conf['cliset'][cli_id]['cli']) + '"');
                                _is_met_conditions_precedent = False;
                                break;
                            if not self._conditions_precedent_is_met(x, self.status['facts'], self.conf['cliset'][i][x]):
                                _is_met_conditions_precedent = False;
                                break;
                    if _is_conditions_match and _is_met_conditions_precedent:
                        display.vv('<' + self.info['host'] + '> condition precedent met for "' + str(self.conf['cliset'][i]['cli']) + '"');
                        self.conf['cliset'][i]['status'] = 'unknown';
                        break;
        except:
            self.errors.append('the evaluation of conditions after "' + str(self.conf['cliset'][cli_id]['cli']) + '" task failed');
            self.conf['cliset'][cli_id]['status'] = 'failed';
            exc_type, exc_value, exc_traceback = sys.exc_info();
            self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
            return 'error';
        return None;


    def _conditions_precedent_is_met(self, ctype, facts, conditions):
        try:
            if not isinstance(ctype, str):
                self.errors.append('the _conditions_precedent_is_met() does not support non-string condition types: "' + str(type(ctype)) + '"');
                return False;
            if ctype not in ['conditions_precedent_all']:
                self.errors.append('the _conditions_precedent_is_met() does not support type "' + ctype + '" conditions');
                return False;
            if not isinstance(facts, dict):
                self.errors.append('the _conditions_precedent_is_met() does not support non-dictionary "facts"');
                return False;
            if not isinstance(conditions, list):
                self.errors.append('the _conditions_precedent_is_met() does not support non-list "conditions"');
            if len(facts) == 0:
                return;
            if len(conditions) == 0:
                return;
            _is_satisfied = True;
            for c in conditions:
                m = re.match('^(?P<item>\S+)\s(?P<predicate>eq|ne|ge|gt|lt|le|rgx)\s(?P<value>\S+.*)', c);
                if not m:
                    self.errors.append('the condition "' + str(c) + '" is incompatible with  _conditions_precedent_is_met() function');
                    return False;
                gd = m.groupdict();
                if gd['item'] not in facts:
                    display.vv('<' + self.info['host'] + '> the "' + str(gd['item']) + '" field was not found in existing facts');
                    _is_satisfied = False;
                if gd['predicate'] == 'rgx':
                    if not re.match(str(gd['value']), str(facts[gd['item']])):
                        display.vv('<' + self.info['host'] + '> the "' + str(gd['item']) + '" field in facts does not match regex pattern "' + str(gd['value']) + '"');
                        _is_satisfied = False;
                elif gd['predicate'] in ['eq', 'ne']:
                    if gd['predicate'] == 'eq':
                        if str(facts[gd['item']]) != str(gd['value']).strip():
                            display.vv('<' + self.info['host'] + '> the "' + str(gd['item']) + '" field in facts is not equal to "' + str(gd['value']) + '" when predicate is eq');
                            _is_satisfied = False;
                    else:
                        if str(facts[gd['item']]) == str(gd['value']).strip():
                            display.vv('<' + self.info['host'] + '> the "' + str(gd['item']) + '" field in facts is equal to "' + str(gd['value']) + '" when predicate is ne');
                            _is_satisfied = False;
                else:
                    '''
                    This is purely mathematical computation for ge, gt, le, lt.
                    '''
                    if not re.match('^\d+$', str(facts[gd['item']]).strip()) or not re.match('^\d+$', str(gd['value']).strip()):
                        _is_satisfied = False;
                    v1 = int(str(facts[gd['item']]).strip())
                    v2 = int(str(gd['value']).strip())
                    if gd['predicate'] == 'ge':
                        if v1 < v2:
                            display.vv('<' + self.info['host'] + '> the "' + str(gd['item']) + '" field in facts is less than "' + str(gd['value']) + '" when predicate is ge');
                            _is_satisfied = False;
                    elif gd['predicate'] == 'gt':
                        if v1 <= v2:
                            display.vv('<' + self.info['host'] + '> the "' + str(gd['item']) + '" field in facts is less than or equal to "' + str(gd['value']) + '" when predicate is gt');
                            _is_satisfied = False;
                    elif gd['predicate'] == 'le':
                        if v1 > v2:
                            display.vv('<' + self.info['host'] + '> the "' + str(gd['item']) + '" field in facts is greater than "' + str(gd['value']) + '" when predicate is le');
                            _is_satisfied = False;
                    elif gd['predicate'] == 'lt':
                        if v1 >= v2:
                            display.vv('<' + self.info['host'] + '> the "' + str(gd['item']) + '" field in facts is greater than or equal to "' + str(gd['value']) + '" when predicate is lt');
                            _is_satisfied = False;
                    pass;
                if not _is_satisfied:
                    return False;
            if not _is_satisfied:
                return False;
        except:
            self.errors.append('the evaluation failed for facts "' + str(facts) + '" and conditions "' + str(conditions) + '"');
            exc_type, exc_value, exc_traceback = sys.exc_info();
            self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
            return False;
        return True;

    def _match_condition(self, scope='conditions_match_all', cds=[], cli='unknown', stage='unknown'):
        '''
        The scope values of this function are:
          - `conditions_match_any`: must match a sinle condition in any of condition categories
          - `conditions_match_all`: must match all conditions while in a single condition category
          - `conditions_match_all_nolimit`: must match all conditions, regarless whether the
            matches are in different condition categories.
        '''
        i = 0;
        '''
        Tracks regular expression patterns and tags.
        '''
        r = {};
        '''
        Tracks regular expression matches.
        '''
        m = {};
        '''
        Holds all possible tags
        '''
        tags = [];
        '''
        Validate and analyze the patterns.
        '''
        if not isinstance(cds, list):
            display.display('<' + self.info['host'] + '> "' + scope + '" conditional is invalid for cli: "' + str(cli) + '" "' +  str(cds) + '"', color='red');
            self.conf['abort'] = True;
            return False;
        for c in cds:
            r[i] = {};
            if re.match('tag:', c):
                lst = c.split(':');
                if len(lst) < 3:
                    display.display('<' + self.info['host'] + '> "' + scope + '" conditional format invalid: "' + str(c) + '"', color='red');
                    self.conf['abort'] = True;
                    return False;
                lst.pop(0);
                r[i]['tag'] = lst.pop(0);
                r[i]['regex'] = ':'.join(lst);
                if r[i]['tag'] not in self.conf['allowed_ref_tags']:
                    display.display('<' + self.info['host'] + '> "' + scope + '" conditional is unsupported: "' + str(c) + '"', color='red');
                    self.conf['abort'] = True;
                    return False;
                if r[i]['tag'] not in tags:
                    tags.append(r[i]['tag'])
            else:
                if 'configuration' not in tags:
                    tags.append('configuration');
                r[i]['tag'] = 'configuration';
                r[i]['regex'] = c;
            m[i] = False;
            i += 1;

        for t in tags:
            if t not in self.refdb:
                continue;
            fc = self.refdb[t];
            if scope == 'conditions_match_all':
                for j in range(len(m)):
                    m[j] = False;
            for line in fc:
                for j in range(len(m)):
                    if r[j]['tag'] != t:
                        continue;
                    '''
                    TODO: check whether using `search()` makes sense.
                    '''
                    if re.search(r[j]['regex'], line):
                        if scope == 'conditions_match_any':
                            return True;
                        m[j] = True;
                    _match = True;
                    for k in m:
                        if m[k] == False:
                            _match = False;
                            break;
                    if _match:
                        return True;
        return False;


    def _lookup_host_facts(self, fn, cli_id):
        '''
        This function parses the files having `version` tag attached.
        Based on the information, the function finds out the vendor
        of operating system, its name, version, architecture, if any.

        The `allowed_facts` are:
        - `os_vendor`: Cisco, Juniper, Arista, etc.
        - `os_class`: cisco_nxos, cisco_asa, arista_eos, etc.
        - `os_name`: EOS, vEOS, NX-OS, IOS, IOS XE
        - `os_version_major`
        - `os_version_minor`
        - `os_version_patch`
        - `os_arch`: `i386`
        - `os_internal_build_id`
        - `os_internal_build_version`
        - `hardware_vendor`
        - `hardware_platform`
        - `hardware_serial`
        - `hardware_macaddr`

        '''
        display.vv('<' + self.info['host'] + '> checking host facts ... ');
        patterns = None;
        if 'fact_patterns' not in self.conf:
            return;
        if len(self.conf['fact_patterns']) == 0:
            return;
        facts = {}
        try:
            fc = None;
            lines = [];
            with open(fn) as f:
                fc = [x for x in f.readlines()];
            if not fc:
                return;
            for line in fc:
                line = line.rstrip();
                if re.match('^\s*$', line):
                    continue;
                _no_match = True;
                for p in self.conf['fact_patterns']:
                    if 'pattern' not in p:
                        self.errors.append('the host facts lookup failed because "pattern" field is missing from a pattern')
                        self.conf['cliset'][cli_id]['status'] = 'failed';
                        return
                    try:
                        m = re.match(p['pattern'], line, re.I);
                        if m:
                            _no_match = False;
                            gps = m.groupdict();
                            for k in gps:
                                single_fact = str(gps[k]);
                                if 'strip_quotes' in p:
                                    single_fact = single_fact.strip('"');
                                facts[k] = single_fact;
                            if 'add' in p:
                                for t in p['add']:
                                    if len(t.split('=')) != 2:
                                        self.errors.append('the host facts lookup failed because supplemental data "' + str(p['add']) + '" format is invalid');
                                        self.conf['cliset'][cli_id]['status'] = 'failed';
                                        return;
                                    k, v = t.split('=');
                                    facts[k] = v;
                    except:
                        self.errors.append('the host facts lookup failed because pattern "' + str(p['pattern']) + '" is invalid');
                        self.conf['cliset'][cli_id]['status'] = 'failed';
                        exc_type, exc_value, exc_traceback = sys.exc_info();
                        self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
                        return;
                if _no_match:
                    display.vv('facts: no match for: ' + line);
                else:
                    display.vv('facts: match found:  ' + line);
            display.vv(str(facts));
        except:
            self.errors.append('the host facts lookup failed');
            self.conf['cliset'][cli_id]['status'] = 'failed';
            exc_type, exc_value, exc_traceback = sys.exc_info();
            self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
            return;
        # TODO: certain facts require normalization, e.g. `memory_free`: `2902608 kB`, or `uptime`: `2 hours and 40 minutes`
        # TODO: the above is true about `hardware_macaddr`: `0800.2756.4f61`
        if len(facts) > 0:
            if 'facts' not in self.status:
                self.status['facts'] = {};
            for f in facts:
                self.status['facts'][f] = facts[f];
            display.vv('discovered the following facts: ' + str(self.status['facts']));
        return;


    def _lookup_additional_commands(self, fn, cli_id):
        cli = self.conf['cliset'][cli_id]['cli'];
        if 'derivatives' not in self.conf['cliset'][cli_id]:
            return;
        tags = [];
        if 'tags' in self.conf['cliset'][cli_id]:
            for t in self.conf['cliset'][cli_id]['tags']:
                if t not in ['ref:conf', 'configuration', 'conf']:
                    tags.append(t);
        fc = None;
        lines = [];
        with open(fn) as f:
            fc = [x for x in f.readlines()];
        if not fc:
            return;
        derivatives = self.conf['cliset'][cli_id]['derivatives'];
        for derivative in derivatives:
            oslist = derivative['os'];
            patterns = derivative['regex'];
            actions = derivative['actions'];
            _os_not_found = True;
            for _os in oslist:
                if re.match(_os, self.info['os']):
                    _os_not_found = False;
                    break;
            if _os_not_found:
                continue;
            db = {};
            if 'facts' in derivative:
                for fact in derivative['facts']:
                    db[fact] = derivative['facts'][fact];
            for line in fc:
                _break = False;
                flags = [];
                for p in patterns:
                    try:
                        m = re.match(p['pattern'], line);
                        if m:
                            if 'flags' not in p:
                                self.errors.append('the derivative pattern "' + p['pattern'] + '" for "' + str(oslist) + '" has no flags');
                                self.conf['cliset'][cli_id]['status'] = 'failed';
                                break;
                            flags.extend(p['flags']);
                            # FIX: display.display('<' + self.info['host'] + '> match found: ' + str(m.groupdict()), color='red');
                            gd = m.groupdict();
                            if 'purge' in p['flags']:
                                db = {};
                                if 'facts' in derivative:
                                    for fact in derivative['facts']:
                                        db[fact] = derivative['facts'][fact];
                            for k in gd:
                                db[k] = gd[k];
                    except:
                        self.errors.append('the derivative pattern "' + p['pattern'] + '" for "' + str(oslist) + '" is invalid');
                        self.conf['cliset'][cli_id]['status'] = 'failed';
                        exc_type, exc_value, exc_traceback = sys.exc_info();
                        self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
                        break;
                if _break:
                    continue;
                for a in actions:
                    _break = False;
                    if 'add_cli' in flags:
                        for r in a['required']:
                            if r not in db:
                                _break = True;
                                break;
                        if _break:
                            continue;
                        if 'cli' not in a:
                            continue;
                        for x in ['conditions_match_all', 'conditions_match_all_nolimit', 'conditions_match_any']:
                            if x in a:
                                if not self._match_condition(x, a[x], cli, '_lookup_additional_commands()'):
                                    _break = True;
                                    continue;
                        if _break:
                            continue;
                        mc = [];
                        if isinstance(a['cli'], str):
                            mc.append(a['cli']);
                        elif isinstance(a['cli'], list):
                            mc.extend(a['cli']);
                        else:
                            _break = True;
                            break;
                        i = 0;
                        for c in mc:
                            i += 1;
                            for r in a['required']:
                                c = c.replace("<" + r + ">", str(db[r]));
                            cli_entry = {
                                'cli': c,
                                'source': 'derivative',
                                'status': 'unknown',
                                'parent_cli_id': cli_id,
                            }
                            '''
                            The plugin uses the `preserve` attribute to determine whether to
                            copy the file from its temporary directory to output directory.
                            If the attribute exitst and it is set to False, then a temporary
                            file will not be copied.
                            '''
                            for j in ['preserve', 'description']:
                                if j in a:
                                    cli_entry[j] = a[j];
                                    if j == 'description':
                                        for k in db:
                                            cli_entry[j] = str(cli_entry[j]).replace("<" + k + ">", str(db[k]));
                            if 'format' in a:
                                cli_entry['format'] = a['format'];
                            else:
                                cli_entry['format'] = 'txt';
                            if 'saveas' in a:
                                #_saveas = self._normalize_str(str(a['saveas']));
                                _saveas = str(a['saveas']);
                                cli_entry['saveas'] = self._decode_ref(_saveas);
                                cli_entry['filename'] = os.path.basename(cli_entry['saveas']);
                                for k in db:
                                    cli_entry['saveas'] = str(cli_entry['saveas']).replace("<" + k + ">", str(self._normalize_str(db[k])));
                                    cli_entry['filename'] = str(cli_entry['filename']).replace("<" + k + ">", str(self._normalize_str(db[k])));
                                cli_entry['filename'] = self._decode_ref(cli_entry['filename'])
                                '''
                                Although this command is a part of series of commands and the information is written
                                to the same file, there is a need to overwrite any non-temporary file.
                                '''
                                if i == 1:
                                    cli_entry['overwrite'] = True;
                            else:
                                cli_entry['filename'] = self._normalize_str(c, self.info['host'], cli_entry['format']);
                            if 'allow_empty_response' in a:
                                cli_entry['allow_empty_response'] = a['allow_empty_response'];
                            else:
                                cli_entry['allow_empty_response'] = False;
                            for k in ['error_if_all', 'error_if', 'success_if_all', 'success_if']:
                                if k in a:
                                    cli_entry[k] = a[k];
                            if 'mode' in a:
                                cli_entry['mode'] = a['mode'];
                            else:
                                cli_entry['mode'] = 'analytics';
                            if 'derivatives' in a:
                                cli_entry['derivatives'] = a['derivatives'];
                                cli_entry['derivatives'][0]['facts'] = copy.deepcopy(db);
                            '''
                            TODO: this is a remnant of some other thing. check `preserve`
                            '''
                            if 'append' in a:
                                if a['append'] is True:
                                    cli_entry['append'] = True;
                            if tags:
                                cli_entry['tags'] = tags;
                            if 'tags' in a:
                                cli_entry['tags'] = [];
                                if tags:
                                    cli_entry['tags'].extend(tags);
                                if isinstance(a['tags'], str):
                                    cli_entry['tags'].append(a['tags']);
                                elif isinstance(a['tags'], list):
                                    cli_entry['tags'].extend(a['tags']);
                                else:
                                    pass;
                            else:
                                cli_entry['tags'] = tags;
                            if self.conf['allowed_sections'] is not None:
                                _is_not_allowed = True;
                                for s in self.conf['allowed_sections']:
                                    if s in cli_entry['tags']:
                                        _is_not_allowed = False
                                if _is_not_allowed:
                                    continue;
                            '''
                            Here, we filter commands that were already added to the queue
                            '''
                            _is_duplicate_cli = False;
                            for _id in self.conf['cliset']:
                                if not isinstance(self.conf['cliset'][_id], dict):
                                    continue;
                                if 'cli' in self.conf['cliset'][_id]:
                                    if self.conf['cliset'][_id]['cli'] == cli_entry['cli']:
                                        _is_duplicate_cli = True;
                                        break;
                            if _is_duplicate_cli:
                                continue;
                            '''
                            Add derivative command to the queue.
                            '''
                            display.display('<' + self.info['host'] + '> added derivative command to queue: ' + c, color='green');
                            self.conf['cliset_last_id'] += 1;
                            self.conf['cliset'][self.conf['cliset_last_id']] = cli_entry;
                            if 'child_cli_id' not in self.conf['cliset'][cli_id]:
                                self.conf['cliset'][cli_id]['child_cli_id'] = [];
                            self.conf['cliset'][cli_id]['child_cli_id'].append(c);
        return;


    def _parse_cli_output(self, fn, cli_id):
        '''
        The following function returns `False` when there is no errors.
        If there are any issues with the output, it will return `True`.
        '''
        cli = self.conf['cliset'][cli_id]['cli'];
        self._remove_non_ascii(fn);
        self.conf['cliset'][cli_id]['lines'] = self._remove_ltr_blanks(fn);
        if self.conf['cliset'][cli_id]['lines'] == 0:
            #display.v('<' + self.info['host'] + '> testing id: ' + str(cli_id));
            #display.v('<' + self.info['host'] + '> testing file: ' + str(fn));
            #display.v('<' + self.info['host'] + '> testing: ' + str(self.conf['cliset'][cli_id]));
            if self.conf['cliset'][cli_id]['allow_empty_response'] == True:
                return False;
            if self.conf['cliset'][cli_id]['mode'] == 'analytics':
                self.conf['cliset'][cli_id]['status'] = 'retry';
            return True;
        fc = None;
        lines = [];
        with open(fn) as f:
            fc = [x.rstrip() for x in f.readlines()];
        if not fc:
            if self.conf['cliset'][cli_id]['allow_empty_response'] == True:
                return False;
            if self.conf['cliset'][cli_id]['mode'] == 'configure':
                return False;
            self.errors.append('the \'' + str(cli) + '\' command produced no output');
            self.conf['cliset'][cli_id]['status'] = 'failed';
            return True;
        '''
        Secure captured cli output.
        '''
        try:
            os.chmod(fn, stat.S_IRUSR | stat.S_IWUSR);
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info();
            self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
            self.conf['cliset'][cli_id]['status'] = 'failed';
            return True;
        '''
        Check whether the file is used for reference purpose, e.g. configuration
        or version files, and act accordingly.
        '''
        if 'tags' in self.conf['cliset'][cli_id]:
            refs = [];
            for t in self.conf['cliset'][cli_id]['tags']:
                if re.match('ref:', t):
                    rt = t.replace("ref:", "");
                    if rt not in refs:
                        refs.append(rt);
                if t == 'configuration' or t == 'version':
                    if t not in refs:
                        refs.append(t);
            '''
            Found references found.
            '''
            if refs:
                '''
                Store the contents of configuration commands for use in
                conditional statements.
                '''
                for rt in refs:
                    if rt not in self.refdb:
                        self.refdb[rt] = [];
                    self.refdb[rt].extend(fc);
                '''
                Loop through existing conditional commands and decide whether
                any of the command should run.
                '''
                #display.display('<' + self.info['host'] + '> configuration file detected', color='red');
                for i in self.conf['cliset']:
                    if self.conf['cliset'][i]['status'] == 'conditional':
                        display.vv('<' + self.info['host'] + '> found conditional cli task: "' + str(self.conf['cliset'][i]['cli']) + '"');
                        _is_conditions_match = True;
                        _is_met_conditions_precedent = True;
                        for x in ['conditions_match_all', 'conditions_match_all_nolimit', 'conditions_match_any']:
                            if x in self.conf['cliset'][i]:
                                if not self._match_condition(x, self.conf['cliset'][i][x]):
                                    _is_conditions_match = False;
                                    break;
                        for x in ['conditions_precedent_all']:
                            if x in self.conf['cliset'][i]:
                                if 'facts' not in self.status:
                                    display.vv('<' + self.info['host'] + '> no facts available for condition precedent analysis when parsing cli output from "' + str(cli) + '"');
                                    _is_met_conditions_precedent = False;
                                    break;
                                if not self._conditions_precedent_is_met(x, self.status['facts'], self.conf['cliset'][i][x]):
                                    _is_met_conditions_precedent = False;
                                    break;
                        if _is_conditions_match and _is_met_conditions_precedent:
                            self.conf['cliset'][i]['status'] = 'unknown';
                            break;

        '''
        Parse for errors and filter output prior to saving it.
        Additionally, inspect the contents for the purposes of `success_if` and `error_if`
        conditions.
        '''
        _status_db = {};
        _is_eval_status = False;
        for k in ['error_if_all', 'error_if', 'success_if_all', 'success_if']:
            if k in self.conf['cliset'][cli_id]:
                _is_eval_status = True;
                if not isinstance(self.conf['cliset'][cli_id][k], list):
                    self.errors.append('\'' + str(cli) + '\' command failed due to unsupported error_if/success_if evaluation: ' + str(self.conf['cliset'][cli_id][k]));
                    self.conf['cliset'][cli_id]['status'] = 'failed';
                    return True;
                _status_db[k] = {};
                for i, v in enumerate(self.conf['cliset'][cli_id][k]):
                    _status_db[k][i] = { 'pattern': v, 'found': False };

        _is_erred = False;
        for line in fc:
            if not lines and re.match('^\s*$', line):
                continue;
            if not lines and re.match('show\s', line):
                continue;
            '''
            Evaluate output for errors.
            '''
            for err in self.conf['output_errors']:
                if _is_erred:
                    break;
                for rgx in err['regex']:
                    if _is_erred:
                        break
                    if re.search(rgx, line):
                        display.vvv('the line "' + str(line) + '" matches an error pattern "' + str(rgx) + '"');
                        _is_exempt = False;
                        '''
                        Determine whether there is an exception to a rule.
                        '''
                        if 'exception' in err:
                            for exc in err['exception']:
                                if re.search(exc, str(cli)):
                                    _is_exempt = True;
                        '''
                        Determine whether there is a need to elevate privilege level.
                        '''
                        _is_sudo_eligible = True;
                        if 'sudo_eligible' in self.conf['cliset'][cli_id]:
                            if self.conf['cliset'][cli_id]['sudo_eligible'] > 0:
                                _is_sudo_eligible = False;
                        '''
                        Determine whether the rule applies to the operating system of a host.
                        '''
                        _is_os_exempt = True;
                        if 'os' in err:
                            for os_rgx in err['os']:
                                if re.search(os_rgx, str(self.info['os'])):
                                    _is_os_exempt = False;
                        else:
                            _is_os_exempt = False;
                        '''
                        The error is not exempt.
                        '''
                        if not _is_exempt and not _is_os_exempt:
                            if _is_sudo_eligible:
                                if re.search('lack of privilege', err['msg']) and 'os' in err:
                                    if re.search('(' + '|'.join(err['os']) + ')', str(self.info['os'])):
                                        self.conf['cliset'][cli_id]['sudo_eligible'] = 0;
                                        self.conf['cliset'][cli_id]['status'] = 'sudo_eligible';
                                        return True;
                            else:
                                _status_db['status'] = 'failed';
                                _is_erred = True;
                            if self.conf['cliset'][cli_id]['status'] != 'sudo_eligible':
                                _status_db['errors'] = '\'' + str(cli) + '\' command failed due to ' + err['msg'];
                                _status_db['status'] = 'failed';
                                _is_erred = True;
            '''
            Evaluate `success_if` and `error_if` conditions.
            '''
            if _is_eval_status:
                for k in ['error_if_all', 'error_if', 'success_if_all', 'success_if']:
                    if k not in _status_db:
                        continue;
                    for i in _status_db[k]:
                        if re.search(_status_db[k][i]['pattern'], line):
                            _status_db[k][i]['found'] = True;
            _is_removed = False;
            '''
            Perform string removal based on the plugin's `output_filter_remove`
            configuration.
            '''
            for flt in self.conf['output_filter_remove']:
                if 'tags' not in self.conf['cliset'][cli_id]:
                    break;
                if 'configuration' not in self.conf['cliset'][cli_id]['tags']:
                    break;
                if re.match(flt, line):
                    _is_removed = True;
                    break;
            '''
            Perform string substitutions based on the plugin's `output_filter_replace`
            configuration.
            '''
            for flt in self.conf['output_filter_replace']:
                if 'tags' not in self.conf['cliset'][cli_id]:
                    break;
                if 'configuration' not in self.conf['cliset'][cli_id]['tags']:
                    break;
                for rgx in flt['regex']:
                    if re.search(rgx, line):
                        line = re.sub(rgx, flt['replace'], line);
            if not lines and line == '':
                continue;
            if not _is_removed:
                lines.append(line);
        '''
        Write the modified output to file.
        '''
        fm = 'w';
        with open(fn, fm) as f:
            f.write('\n'.join(lines) + '\n');

        '''
        When running in `configure` mode, the plugin records output into
        internal buffers. Later, this information becomes a part of JUnit
        report files.
        '''
        if self.conf['cliset'][cli_id]['mode'] != 'analytics':
            self.conf['cliset'][cli_id]['system_out'] = '\n'.join(lines) + '\n';

        '''
        Add status about `success_if` and `error_if` conditions.
        '''
        if len(_status_db) > 0:
            for k in ['success_if', 'success_if_all', 'error_if', 'error_if_all']:
                if k not in _status_db:
                    continue;
                #display.v('condition: ' + k, host=self.info['host']);
                #display.v('status_db: ' + str(_status_db), host=self.info['host']);
                _is_match_partial = False;
                _is_match_full = True;
                for i in _status_db[k]:
                    if _status_db[k][i]['found'] == True:
                        _is_match_partial = True;
                    else:
                        _is_match_full = False;
                #display.v('_is_match_full: ' + str(_is_match_full), host=self.info['host']);
                #display.v('_is_match_partial: ' + str(_is_match_partial), host=self.info['host']);
                if (k == 'success_if' and _is_match_partial) or (k == 'success_if_all' and _is_match_full):
                    self.conf['cliset'][cli_id]['status'] = 'ok';
                    return False;
                elif (k == 'error_if' and _is_match_partial) or (k == 'error_if_all' and _is_match_full):
                    self.conf['cliset'][cli_id]['status'] = 'failed';
                    if 'errors' in _status_db:
                        self.errors.append(_status_db['errors']);
                    if 'system_err' not in self.conf['cliset'][cli_id]:
                        self.conf['cliset'][cli_id]['system_err'] = [];
                    self.conf['cliset'][cli_id]['system_err'].extend(lines);
                    return True;
                elif (k == 'error_if' and not _is_match_partial and not _is_match_full) or (k == 'error_if_all' and not _is_match_full):
                    self.conf['cliset'][cli_id]['status'] = 'ok';
                    return False;
                else:
                    pass;
        else:
            self.conf['cliset'][cli_id]['status'] = 'ok';
            return False;
        self.conf['cliset'][cli_id]['system_err'] = lines;
        self.conf['cliset'][cli_id]['status'] = 'failed';
        return True;


    @staticmethod
    def _remove_non_ascii(fn):
        if not os.path.exists(fn):
            return;
        if not os.path.isfile(fn):
            return;
        if not os.access(fn, os.R_OK):
            return;
        with open(fn, "r+") as f:
            data = f.read();
            buffer = [];
            for c in data:
                '''
                Allowed ASCII characters (decimal codes) are listed below:
                - `9`:  horizontal tab
                - `10`: NL line feed, new line
                - `11`: vertical tab
                - `13`: carriage return

                It also works in reverse. For example the below characters are excluded
                - `\u0000-\u0008`: all the way to backspace (`BS`)
                - `\u000c`: NP form feed, new page
                - `\u000e-\u001f`: all the way to unit separator (`US`)
                - `\u007f-\uffff`: from `DEL character to the end of the table
                '''
                if (ord(c) > 31 and ord(c) < 127) or ord(c) in [9, 10, 13]:
                    buffer.append(c);
                elif ord(c) == 11:
                    buffer.append('\t');
                else:
                    pass;
            f.seek(0);
            f.write(''.join(buffer));
            f.truncate();
        return;


    def _remove_ltr_blanks(self, fn):
        if not os.path.exists(fn):
            display.v('<' + self.info['host'] + '> file does not exist: ' + str(fn));
            return 0;
        if not os.path.isfile(fn):
            display.v('<' + self.info['host'] + '> is not a file: ' + str(fn));
            return 0;
        if not os.access(fn, os.R_OK):
            display.v('<' + self.info['host'] + '> is not readable: ' + str(fn));
            return 0;
        '''
        This function removes leading and trailing blank lines from a file.
        Additionally, it returns the number of lines in the file.
        The count does not include the leading or trailing blank lines.
        '''
        lc = 0;
        lines = None;
        with open(fn, 'r') as f:
            lines = f.readlines();
        '''
        The content of a file is not available.
        '''
        if not lines:
            return lc;
        '''
        Files with a single empty line.
        '''
        if len(lines) == 1:
            if re.match('^\s*$', str(lines[0]).rstrip()):
                return 0;
            if re.match('show\s', str(lines[0]).rstrip()):
                return 0;
        '''
        Determine which lines are empty.
        '''
        empty_lines = [];
        for i in [(0, len(lines), 1), (len(lines)-1, -1, -1)]:
            for j in xrange(i[0], i[1], i[2]):
                if re.match('^\s*$', lines[j].rstrip()):
                    if j not in empty_lines:
                        empty_lines.append(j);
                else:
                    break;
        if empty_lines:
            empty_lines = list(reversed(sorted(empty_lines)));
            for empty_line in empty_lines:
                lines.pop(empty_line);
        if not lines:
            return lc;
        with open(fn, 'w') as f:
            f.write(''.join(lines));
        return len(lines);


    def _decode_ref(self, s):
        '''
        This function translates references to special codes in string variables:
        - `%p`: Task UUID
        - `%P`: Playbook UUID
        - `%h`: Hostname
        - `%F`: FQDN
        - `%Y`: Year with century as a decimal number
        - `%m`: Month as a zero-padded decimal number
        - `%d`: Day of the month as a zero-padded decimal number
        - `%H`: Hour (24-hour clock) as a zero-padded decimal number
        - `%M`: Minute as a zero-padded decimal number
        - `%S`: Second as a zero-padded decimal number
        - `%E`: Epoch
        '''

        for i in self.refs:
            s = s.replace('%' + i, self.refs[i]);
        s = s.replace('%', '');
        return s;


    def _load_conf(self):
        '''
        This function loads the configuration of this plugin.
        '''
        fc = None;
        try:
            with open(self.plugin_conf) as f:
                fc = yaml.load(f);
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info();
            display.v('an attempt to read ' + self.plugin_name + ' configuration data from ' + str(self.plugin_conf) + ' failed.', host=self.info['host']);
            for i in traceback.format_exception(exc_type, exc_value, exc_traceback):
                for j in i.split('\n'):
                    if j == '':
                        continue;
                    display.v(j, host=self.info['host']);
            raise AnsibleError(exc_value);
        for i in ['allowed_os', 'output_filter_remove', 'output_filter_replace', 'output_errors', 'allowed_ref_tags', 'allowed_formats']:
            if i in fc:
                self.conf[i] = fc[i];
        return;


    def _load_exceptions(self):
        '''
        This function loads the exceptions for cli sets of this plugin.
        '''
        fc = None;
        try:
            with open(self.conf['cliset_exc']) as f:
                fc = yaml.load(f);
        except:
            return;
        optional_fields = ['host', 'cli', 'os', 'description'];
        if 'exceptions' not in fc:
            return;
        if not isinstance(fc['exceptions'], list):
            raise AnsibleError("the plugin exceptions file '" + str(self.conf['cliset_exc']) + "' must be a list of dictionaries");
        for r in fc['exceptions']:
            if not isinstance(r, dict):
                raise AnsibleError("the plugin exceptions file '" + str(self.conf['cliset_exc']) + "' must be a list of dictionaries");
            _is_valid = False;
            for i in optional_fields:
                if i not in r:
                    continue;
                _is_valid = True;
                if not isinstance(r[i], str):
                    raise AnsibleError('the "' + i + '" mandatory field in the plugin\'s exceptions file "' + \
                            str(self.conf['cliset_exc']) + '" must be a string with a valid regular expression');
            for i in r:
                if i not in optional_fields:
                    raise AnsibleError("the plugin exceptions file '" + str(self.conf['cliset_exc']) + "' contains unsupported category: " + str(i));
            if not _is_valid:
                raise AnsibleError('cli exceptions file "' + str(self.conf['cliset_exc']) + '" is missing "' + i + '" mandatory field');
            if 'exceptions' not in self.conf:
                self.conf['exceptions'] = [];
            self.conf['exceptions'].append(r);
        return;


    def _load_credentials(self, db=dict()):
        '''
        Load access credentials from Ansible Vault file.
        '''
        credentials = [];
        rgx_credentials = {};
        dft_credentials = {};
        allowed_credentials_fields = [
            'regex',
            'username',
            'password',
            'password_enable',
            'priority',
            'description',
            'default',
            'token',
            'pin',
            'api_auth_key',
            'api_auth_value',
        ];
        #self.errors.append('XXXX: ' + str(db));
        for c in db:
            for k in c:
                if k not in allowed_credentials_fields:
                    self.errors.append('access credentials dictionary contains invalid key: ' + k);
            required_keys = None;
            required_keys_shell = ['username', 'password', 'priority'];
            required_keys_api = ['api_auth_key', 'api_auth_value'];
            if self._is_api_driven:
                required_keys = copy.deepcopy(required_keys_api);
            else:
                required_keys = copy.deepcopy(required_keys_shell);
            for k in required_keys:
                break;
                if k not in c:
                    self.errors.append('the "' + str(c) + '" access credentials entry is missing mandatory key "' + k + '"');
                    return None;
            if 'regex' not in c and 'default' not in c:
                self.errors.append('access credentials dictionary has neither regex nor default keys: ' + str(c));
                return None;
            elif 'regex' in c and 'default' in c:
                if c['default'] is True:
                    self.errors.append('access credentials entry must have either \'regex\' key or \'default\' key must be set to \'True\': ' + str(c));
                    return None;
                else:
                    if re.match(c['regex'], self.info['host']):
                        if c['priority'] in rgx_credentials:
                            for k in ['password', 'password_enable']:
                                if k in c:
                                    del c[k];
                                if k in rgx_credentials[c['priority']]:
                                    del rgx_credentials[c['priority']][k];
                            self.errors.append('access credentials entry "' + str(c) + '" has the same priority as "' + str(rgx_credentials[c['priority']])  + '"');
                            return None;
                        rgx_credentials[c['priority']] = c.copy();
                        continue;
            elif 'regex' not in c and 'default' in c:
                if c['default'] is False:
                    self.errors.append('access credentials entry must have either \'regex\' key or \'default\' key must be set to \'True\': ' + str(c));
                    continue;
                else:
                    if c['priority'] in dft_credentials:
                        for k in ['password', 'password_enable']:
                            if k in c:
                                del c[k];
                            if k in rgx_credentials[c['priority']]:
                                del rgx_credentials[c['priority']][k];
                        self.errors.append('default access credentials entry "' + str(c) + '" has the same priority as "' + str(dft_credentials[c['priority']])  + '"');
                        return None;
                    dft_credentials[c['priority']] = c.copy();
                    continue;
            elif 'regex' in c and 'default' not in c:
                if re.match(c['regex'], self.info['host']):
                    if c['priority'] in rgx_credentials:
                        for k in ['password', 'password_enable']:
                            if k in c:
                                del c[k];
                            if k in rgx_credentials[c['priority']]:
                                del rgx_credentials[c['priority']][k];
                        self.errors.append('access credentials entry "' + str(c) + '" has the same priority as "' + str(rgx_credentials[c['priority']])  + '"');
                        return None;
                    rgx_credentials[c['priority']] = c.copy();
                    continue;
        if not rgx_credentials and not dft_credentials:
            self.errors.append('access credentials dictionary must have at least one default entry');
            return None;

        for c in sorted(rgx_credentials):
            if 'password_enable' not in rgx_credentials[c]:
                rgx_credentials[c]['password_enable'] = rgx_credentials[c]['password'];
            credentials.append(rgx_credentials[c]);
        for c in sorted(dft_credentials):
            if 'password_enable' not in dft_credentials[c]:
                dft_credentials[c]['password_enable'] = dft_credentials[c]['password'];
            credentials.append(dft_credentials[c]);
        return credentials;


    def _load_cliset(self, fn, src, commit=True):
        '''
        This function is responsible for loading files from the repository of cli commands
        into current process configuration database.

        Each cli command has a number of attributes.
        - `status`:
          * `ok`: worked as expected
          * `failed`
          * `skipped`
          * `conditional`: assigned when entered into the database and has `conditions_match` clause
             additionally it is assigned when `conditions_precedent_all`
          * `retry`
          * `unknown`: assigned when entered into the database
        - `mode`:
          * `noop`
          * `analytics`
          * `configure`
          * `pre`
          * `post`
          * `analytics-append`
        '''
        if not os.path.exists(fn):
            return False;
        if not os.path.isfile(fn):
            self.errors.append(fn + ' is not a file');
            return False;
        if not os.access(fn, os.R_OK):
            self.errors.append(fn + ' is not readable');
            return False;
        fc = None;
        try:
            with open(fn) as f:
                fc = yaml.load(f);
        except:
            self.errors.append('an attempt to read ' + self.plugin_name + ' data from ' + str(fn) + ' failed.');
            exc_type, exc_value, exc_traceback = sys.exc_info();
            self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
            return False;
        if not fc:
            self.errors.append('an attempt to read ' + self.plugin_name + ' data from ' + str(f) + ' failed because no data was found.');
            return False;
        if 'ndmtk' not in fc:
            self.errors.append('the ' + self.plugin_name + ' data from ' + str(fn) + ' does not have reference to \'ndmtk\' list.');
            return False;
        if 'clisets' not in self.status:
            self.status['clisets'] = [];
        self.status['clisets'].append(fn);
        for entry in fc['ndmtk']:
            _continue = False;
            entry_tags = [];
            if not isinstance(entry, dict):
                self.errors.append('the ' + self.plugin_name + ' data from ' + str(fn) + ' is not a list of dictionaries.');
                return False;
            required_keys = ['cli'];
            optional_keys = [
                'tags', 'paging', 'format', 'scripting', 'mode', 'pre', 'post', 'saveas',
                'conditions_match_any', 'conditions_match_all', 'conditions_match_all_nolimit',
                'derivatives', 'preserve', 'description', 'allow_empty_response', 'conditions_precedent_all',
                'os', 'no_newline', 'error_if_all', 'error_if', 'success_if_all', 'success_if',
                'timeout',
            ];
            for k in required_keys:
                if k not in entry:
                    self.errors.append('failed to find mandatory field  \'' + str(k) + '\' in ' + str(entry) + ' in ' + str(fn));
                    continue;
            for k in entry:
                if k not in optional_keys and k not in required_keys:
                    self.errors.append('the \'' + str(k)  + '\' field in ' + str(entry) + ' in ' + str(fn) + ' is unsupported');
                    continue;
                if k == 'os':
                    os_lst = [];
                    if isinstance(entry[k], str):
                        os_lst.append(entry[k]);
                    elif isinstance(entry[k], list):
                        os_lst.extend(entry[k]);
                    else:
                        self.errors.append('the handling of \'' + k  + '\' field of ' + str(type(entry[k])) + ' type in ' + str(entry) + ' in ' + str(fn) + ' is unsupported');
                    if 'os' in self.info:
                        if self.info['os'] not in os_lst:
                            '''
                            The entry (rule) contains `os` filter. This host is not in the list of operating systems covered by this rule.
                            '''
                            _continue = True;
                            break;
                if k in ['paging', 'scripting']:
                    self.conf[k] = entry[k];
                elif k == 'tags':
                    if isinstance(entry[k], str):
                        entry_tags.append(entry[k]);
                    elif isinstance(entry[k], list):
                        entry_tags.extend(entry[k]);
                    else:
                        self.errors.append('the handling of \'' + k  + '\' field of ' + str(type(entry[k])) + ' type in ' + str(entry) + ' in ' + str(fn) + ' is unsupported');
                else:
                    pass;

            if _continue:
                continue;
            '''
            Add additional tags based on references.
            '''
            reference_tags = [];
            for t in entry_tags:
                if re.match('ref:', t):
                    reference_tag = str(t).replace("ref:", "");
                    if reference_tag in entry_tags:
                        continue;
                    if reference_tag in reference_tags:
                        continue;
                    if reference_tag not in self.conf['allowed_ref_tags']:
                        self.errors.append('the \'' + reference_tag  + '\' is not supported in ' + str(fn));
                    reference_tags.append(reference_tag);
            if reference_tags:
                entry_tags.extend(reference_tags);

            '''
            By default, the plugin uses `analytics` mode.
            '''

            entry_mode = 'analytics';
            if 'mode' in entry:
                if entry['mode'] not in ['analytics', 'configure']:
                    self.errors.append('mode "' + str(entry['mode']) + '" is unsupported');
                entry_mode = str(entry['mode']);

            '''
            By default, the entries in the internal database will not be created
            if loading from python's site-packages plugin directory `files/cli/os`.
            It is used to validate the integrity and quality of the default entries.
            '''

            if not commit:
                continue;

            '''
            By default, the plugin does not allow to run show tech type commands.
            '''

            if 'show_tech' in self.conf:
                if self.conf['show_tech'] == False and 'tech-support' in entry_tags:
                    display.vv('skipped cli command \'' + entry['cli'] + '\' due to show_tech is set to no', host=self.info['host']);
                    continue;

            '''
            When the plugin was envokes with `sections` parameter, the tags provided
            in the section are matched against the tags associated with a command.
            If there is no match, then the plugin goes to the next command in its
            queue.
            
            It also means that the plugin will NOT create an entry in the
            internal database, i.e. an entry with `skipped` status.
            '''

            if self.conf['allowed_sections'] is not None:
                _is_not_allowed = True;
                for s in self.conf['allowed_sections']:
                    if s in entry_tags:
                        _is_not_allowed = False
                if _is_not_allowed:
                    continue;

            '''
            The plugin supports the following output formats:
            - `txt` and `out`
            - `json`
            - `xml`
            '''

            if self.conf['allowed_formats']:
                if 'format' in entry:
                    if entry['format'] not in self.conf['allowed_formats']:
                        self.errors.append('the \'' + str(entry['format'])+ '\' is not supported in ' + str(fn));

            '''
            The execution stops if the plugin encounters errors.
            '''

            if self.errors:
                return False;

            '''
            If no errors, then the plugin creates the entries in its internal
            execution database.

            If the `sections` for the entries does not exists (i.e. `cliset`),
            it is created.

            Also, the `cliset_last_eid` gets initialized. It tracks the last
            executed command. It is critical variable, because the plugin uses
            it to decide task sequence via `_get_cli_task()` function.
            '''

            if 'cliset' not in self.conf:
                self.conf['cliset'] = OrderedDict();
                self.conf['cliset_last_eid'] = 0;

            '''
            By default, the plugin does not support mixing `analytics` and `configure` modes.
            When the plugin detects duplicate commands it stops populating the database.
            The exception is where the mode is `noop`.

            TODO: This maybe an issue with `configure` mode, e.g. applying `shutdown` to multiple interfaces.
            '''

            _is_duplicate_cli = False;
            if entry_mode != 'configure':
                for c in self.conf['cliset']:
                    if 'cli' not in self.conf['cliset'][c]:
                        continue;
                    if self.conf['cliset'][c]['cli'] == entry['cli']:
                        if entry_mode != 'noop':
                            _is_duplicate_cli = True;
                            display.vv('duplicate cli command \'' + entry['cli'] + '\'', host=self.info['host']);
                    if self.conf['cliset'][c]['mode'] != entry_mode:
                        if entry_mode == 'noop' or self.conf['cliset'][c]['mode'] == 'noop':
                            continue;
                        if 'pre' in entry and 'post' in entry:
                            _is_duplicate_cli = False;
                            continue;
                        if 'saveas' in entry:
                            _is_duplicate_cli = False;
                            continue;
                        self.errors.append('the plugin does not support the mixing of \'configure\' and \'analytics\' modes in the same run');
                        return False;
            if _is_duplicate_cli:
                continue;

            '''
            At times, there is a need to run commands as a condition precedent.
            The `pre` attribute is designed to accomplish this.

            Also, the `cliset_last_id` variable is created to record the total number of
            commands in the database.

            TODO: create dependency list for `cliset_last_id`
            TODO: handle multiline commands
            TODO: get rid of empty line comparison
            '''

            if 'pre' in entry:
                entry_tasks_pre = filter(lambda x: len(x) > 0, entry['pre'].split('\n'));
                for entry_task in entry_tasks_pre:
                    if entry_task.strip() == '':
                        continue;
                    self.conf['cliset_last_id'] += 1;
                    self.conf['cliset'][self.conf['cliset_last_id']] = {
                        'format': 'txt',
                        'filename': 'response.' + str(self.conf['cliset_last_id']) + '.txt',
                        'source': 'src',
                        'cli': entry_task,
                        'mode': 'pre',
                        'status': 'unknown',
                        'allow_empty_response': True,
                    };

            '''
            The plugin supports multiline command input.

            TODO: add support for multiline command input, where `cli` is `list` instead of `str` with newlines
            TODO: remove `response.` from `filename` and zero fill 8 characters.
            TODO: review `noop` operation
            TODO: review `configuration` and `version` settings
            '''

            entry_tasks = entry['cli'].split('\n');
            for entry_task in entry_tasks:
                if entry_task.strip() == "":
                    continue;
                self.conf['cliset_last_id'] += 1;
                c = {
                    'cli': entry_task,
                    'source': src,
                    'mode': entry_mode,
                    'status': 'unknown',
                };
                '''
                The default format of the entries is `txt`.
                '''
                if 'format' in entry:
                    c['format'] = entry['format'];
                else:
                    c['format'] = 'txt';
                if 'saveas' in entry:
                    c['filename'] = self._decode_ref(entry['saveas']);
                else:
                    if entry_mode == 'configure':
                        c['filename'] = 'response.' + str(self.conf['cliset_last_id']) + '.txt';
                    else:
                        c['filename'] = self._normalize_str(entry_task, self.info['host'], c['format']);
                for j in ['preserve', 'description', 'allow_empty_response', 'derivatives', 'no_newline', 'error_if_all', 'error_if', 'success_if_all', 'success_if', 'timeout']:
                    if j in entry:
                        c[j] = entry[j];
                '''
                Check whether the command is dependent on a condition precedent.
                '''
                for x in ['conditions_match_all', 'conditions_match_all_nolimit', 'conditions_match_any', 'conditions_precedent_all']:
                    if x in entry:
                        c['status'] = 'conditional';
                        c[x] = entry[x];
                '''
                By default, produce error when empty response is received.
                '''
                if 'allow_empty_response' not in entry:
                    c['allow_empty_response'] = False;
                if entry_tags:
                    c['tags'] = entry_tags;
                if 'exceptions' in self.conf and entry_mode == 'analytics':
                    for r in self.conf['exceptions']:
                        if 'cli' in r:
                            if not re.match(r['cli'], entry_task):
                                continue;
                        if 'host' in r:
                            if not re.match(r['host'], self.info['host']):
                                continue;
                        if 'os' in r:
                            if not re.match(r['os'], self.info['os']):
                                continue;
                        c['status'] = 'skipped';
                        c['mode'] = 'noop';

                '''
                The command is added to the database and is assigned `id` based on
                the value of `cliset_last_id`.
                '''
                self.conf['cliset'][self.conf['cliset_last_id']] = c;

            if 'post' in entry:
                entry_post_tasks = filter(lambda x: len(x) > 0, entry['post'].split('\n'));
                for entry_task in entry_post_tasks:
                    if entry_task.strip() == '':
                        continue;
                    self.conf['cliset_last_id'] += 1;
                    self.conf['cliset'][self.conf['cliset_last_id']] = {
                        'format': 'txt',
                        'filename': 'response.' + str(self.conf['cliset_last_id']) + '.txt',
                        'source': 'src',
                        'cli': entry_task,
                        'mode': 'post',
                        'status': 'unknown',
                        'allow_empty_response': True,
                    };

            for t in entry_tags:
                if t in ['version', 'configuration'] and 'cli' in entry:
                    self.conf[t] = entry['cli'];
        return True;


    def _report(self):
        '''
        This function creates JUnit report and metadata YAML file for each of the hosts in a run.
        '''
        if 'cliset' not in self.conf:
            return;

        metadata = {
            'conf': self.info,
            'cli': [],
        };

        '''
        This dataset has the following structure: _ds[testuite][testcase][testinfo].
        '''
        _ds = {};

        '''
        Define reported fields
        '''
        reported_fields = [
            'description',
            'cli',
            'allow_empty_response',
            'mode',
            'format',
            'path',
            'path_tmp',
            'sha1',
            'sha1_pre',
            'source',
            'tags',
            'pre',
            'post',
            'saveas',
            'lines',
            'status',
            'retries',
            'child_cli_id',
            'sudo_eligible',
            'conditions_precedent_all',
            'time',
            'time_start',
            'timestamp',
        ];

        '''
        Collect log files
        '''
        _logs = {};
        for i in ['log', 'stdout', 'dbg', 'log_connect', 'log_disconnect']:
            if i not in self.conf:
                continue;
            if not os.path.exists(self.conf[i]):
                continue;
            if not os.path.isfile(self.conf[i]):
                continue;
            if not os.access(self.conf[i], os.R_OK):
                continue;
            with open(self.conf[i], 'r') as f:
                fc = f.readlines();
                if fc:
                    _logs[i] = fc;

        '''
        Gather information about session connection..
        '''
        for _ts_name in ['connect', 'execute', 'disconnect']:
            if _ts_name not in _ds:
                _ds[_ts_name] = {
                    'errors': 0,
                    'skipped': 0,
                    'tests': 0,
                    'failures': 0,
                    'testcases': [],
                    'properties': [],
                    'time': '0.00',
                };
        for _ts_name in ['connect', 'disconnect']:
            _ds[_ts_name]['tests'] += 1;
            if self._play_context.check_mode:
                _ds[_ts_name]['skipped'] = 1;
            elif 'authenticated' not in self.status:
                _ds[_ts_name]['skipped'] = 1;
            else:
                if _ts_name == 'connect' and 'authorized' in self.status:
                    if self.status['authorized'] != 'yes':
                        _ds[_ts_name]['failures'] = 1;
                elif _ts_name == 'disconnect' and 'disconnected' in self.status:
                    if self.status['disconnected'] != 'yes':
                        _ds[_ts_name]['failures'] = 1;
                else:
                    pass;
            if _ts_name + '_start' in self.status and _ts_name + '_end' in self.status:
                _ds[_ts_name]['time'] = (self.status[_ts_name + '_end'] - self.status[_ts_name + '_start']) / 1000;
            if _ts_name + '_start' in self.status:
                _ds[_ts_name]['timestamp'] = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(self.status[_ts_name + '_start'] / 1000));
            '''
            Add extra properties related to establishing connectivity.
            '''
            if _ts_name == 'connect':
                for p in ['host', 'os']:
                    _ds[_ts_name]['properties'].append((p, str(self.info[p])));
                for p in ['output_dir', 'on_error', 'on_prompt', 'temp_dir', 'args', 'play_uuid', 'task_uuid']:
                    if p in self.conf:
                        if p in ['args']:
                            _ds[_ts_name]['properties'].append((p, ' '.join(self.conf[p])));
                        else:
                            _ds[_ts_name]['properties'].append((p, str(self.conf[p])));
                for p in ['return_code', 'return_status', 'return_msg', 'paging_mode', 'scripting_mode', 'prompt_mode', 'clisets']:
                    if p in self.status:
                        if p == 'clisets':
                            for i, v in enumerate(self.status[p]):
                                _ds[_ts_name]['properties'].append( (p + '.' + str(i), str(v)));
                        else:
                            _ds[_ts_name]['properties'].append( (p, str(self.status[p]) ));
            '''
            Both `connect` and `disconnect` test suites have a single testcase.

            Collect the log files associates with session connectivity.
            '''
            flt = [];
            if _ts_name == 'connect':
                flt.extend(['log_connect']);
            if _ts_name == 'disconnect':
                flt.extend(['log_disconnect', 'dbg', 'log', 'stdout']);
            _logs_names = {
                'log':            'default log',
                'log_connect':    'connection establishment log ',
                'log_disconnect': 'connection termination log',
                'dbg':            'shell log',
                'stdout':         'standard output',
            };
            '''
            Write logs and error messages, if any, to either system_out or system_err.
            '''

            _tc = {};
            if 'return_errors' in self.status:
                _logs_out = [];
                _logs_out.append(("#" * 80) + '\n# Errors\n' + ("#" * 80) + '\n\n');
                for i in self.status['return_errors']:
                    _logs_out.append(i + '\n');
                _logs_out.append('\n');
                _tc['system_err'] = ''.join(_logs_out);
            for i in flt:
                if i not in _logs:
                    continue;
                if len(_logs[i]) > 0:
                    _logs_out = [];
                    _logs_out.append(("#" * 80) + '\n# ' + _logs_names[i] + ':\n# ' + self.conf[i] + '\n' + ("#" * 80) + '\n\n');
                    _logs_out.extend(_logs[i]);
                    if i in ['dbg']:
                        if 'system_err' in _tc:
                            _tc['system_err'] += ''.join(_logs_out);
                        else:
                            _tc['system_err'] = ''.join(_logs_out);
                    else:
                        if 'system_out' in _tc:
                            _tc['system_out'] += ''.join(_logs_out);
                        else:
                            _tc['system_out'] = ''.join(_logs_out);
            if 'failures' in _ds[_ts_name]:
                if _ds[_ts_name]['failures'] > 0:
                    _tc['status'] = 'failed';
            _tc['name'] = _ts_name;
            if 'status' not in _tc:
                _tc['status'] = 'ok';
            if 'time' in _ds[_ts_name]:
                _tc['time'] = _ds[_ts_name]['time'];
            _ds[_ts_name]['testcases'].append(_tc);

        '''
        At this point, the test suite switches to the tasks related to the execution of cli commands.
        '''
        _ts_name = 'execute';
        if 'time_end' in self.conf and 'time_start' in self.conf:
            _ds[_ts_name]['time'] = (self.conf['time_end'] - self.conf['time_start']) / 1000;
        if 'time_start' in self.conf:
            _ds[_ts_name]['timestamp'] = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(self.conf['time_start'] / 1000));
        for _id in self.conf['cliset']:
            h = self.conf['cliset'][_id];
            _ds[_ts_name]['tests'] += 1;
            if 'status' in h:
                if h['status'] == 'failed':
                    _ds[_ts_name]['failures'] += 1;
                elif h['status'] in ['skipped', 'conditional', 'retry', 'unknown']:
                    _ds[_ts_name]['skipped'] += 1;
                elif h['status'] == 'ok':
                    pass;
                else:
                    self.errors.append('the status "' + str(h['status'])  + '" is unsupported');
            if 'system_err' in h and h['status'] != 'failed':
                _ds[_ts_name]['failures'] += 1;
            '''
            Record for metadata.
            '''
            hm = {'_seq': _id};
            for p in reported_fields:
                if p in h:
                    if isinstance(h[p], list):
                        hm[p] = list(h[p]);
                    elif isinstance(h[p], dict):
                        hm[p] = copy.deepcopy(h[p]);
                    elif isinstance(h[p], bool):
                        hm[p] = h[p];
                    else:
                        hm[p] = str(h[p]);
            metadata['cli'].append(hm);
            '''
            Gather information about a testcase.
            '''
            _tc = {
                'name': h['cli'],
                'time': '0.00',
            };
            if 'description' in h:
                _tc['name'] = h['description'];
            if 'time_start' in h and 'time_end' in h:
                _tc['time'] = (h['time_end'] - h['time_start']) / 1000;
            '''
            Gather information about each testcase/command.
            '''
            if 'tags' in h:
                _tc['classname'] = ', '.join(h['tags']);
            _tc['status'] = 'unknown';
            if 'status' in h:
                _tc['status'] = h['status'];
            if 'system_out' not in _tc:
                _tc['system_out'] = '';
            if 'parent_cli_id' in h or 'child_cli_id' in h:
                if 'parent_cli_id' in h:
                    _tc['system_out'] += '$ ' + str( self.conf['cliset'][h['parent_cli_id']]['cli']) + '\n';
                    _tc['system_out'] += '|--> $ ' + str(h['cli']) + '\n';
                if 'child_cli_id' in h:
                    _tc['system_out'] += '$ ' + str(h['cli']) + '\n';
                    for c in h['child_cli_id']:
                        _tc['system_out'] += '|--> $ ' + str(c) + '\n';
            else:
                if 'description' in h:
                    _tc['system_out'] += '$ ' + str(h['cli']) + '\n';
            for s in ['out', 'err']:
                if 'system_' + s in h:
                    if isinstance(h['system_' + s], list):
                        _tc['system_' + s] = '\n'.join(h['system_' + s]);
                    else:
                        _tc['system_' + s] = str(h['system_' + s]);
            _ds[_ts_name]['testcases'].append(_tc);
        '''
        Building JUnit XML.
        '''
        z = 0;
        x = ['<?xml version="1.0" encoding="UTF-8"?>'];
        x.append('<testsuites>');
        z += 1;
        for _ts_name in ['connect', 'execute', 'disconnect']:
            _ts = '<testsuite';
            _ts += ' hostname="' + self.info['host'] + '"';
            _ts += ' name="' + self.plugin_name + '.' + _ts_name + '"';
            for _attr in ['errors', 'skipped', 'tests', 'failures', 'time', 'timestamp']:
                if _attr in _ds[_ts_name]:
                    _ts += ' ' + str(_attr)+ '="' + str(_ds[_ts_name][_attr]) + '"';
            _ts += '>';
            x.append(self._indent(z) + _ts);
            z += 1;
            if 'properties' in _ds[_ts_name]:
                if len(_ds[_ts_name]['properties']) > 0:
                    x.append(self._indent(z) + '<properties>');
                    z += 1;
                    for _tp in _ds[_ts_name]['properties']:
                        x.append(self._indent(z) + '<property name="' + _tp[0] + '" value="' + str(_tp[1]) + '"/>');
                    z -= 1;
                    x.append(self._indent(z) + '</properties>');
            for t in _ds[_ts_name]['testcases']:
                _tc = '<testcase';
                for _attr in ['name', 'assertions', 'classname', 'status', 'time']:
                    if _attr in t:
                        _tc += ' ' + str(_attr)+ '="' + str(t[_attr]) + '"';
                _is_testcast_empty = False;
                if t['status'] == 'ok':
                    _is_testcast_empty = True;
                    for _attr in ['system_out', 'system_err']:
                        if _attr in t:
                            if len(t[_attr]) > 0:
                                _is_testcast_empty = False
                                break;
                if _is_testcast_empty:
                    _tc += '/>';
                    x.append(self._indent(z) + _tc);
                    continue;
                _tc += '>';
                x.append(self._indent(z) + _tc);
                z += 1;
                for _attr in ['system_out', 'system_err']:
                    if _attr not in t:
                        continue;
                    if len(t[_attr]) == 0:
                        continue;
                    x.append(self._indent(z) + '<' + _attr + '><![CDATA[');
                    z += 1;
                    x.append(str(t[_attr]).rstrip());
                    x.append(']]>');
                    z -= 1;
                    x.append(self._indent(z) + '</' + _attr + '>');
                if 'status' in t:
                    if t['status'] == 'failed':
                        x.append(self._indent(z) + '<failure/>');
                    elif t['status'] in ['skipped', 'conditional', 'retry', 'unknown']:
                        x.append(self._indent(z) + '<skipped/>');
                    else:
                        pass;
                z -= 1;
                x.append(self._indent(z) + '</testcase>');
            z -= 1;
            x.append(self._indent(z) + '</testsuite>');
        z -= 1;
        x.append(self._indent(z) + '</testsuites>');
        for s in ['temp_dir', 'output_dir', 'args', 'play_uuid', 'task_uuid']:
            if s in self.conf:
                if s in ['args']:
                    metadata[s] = ' '.join(self.conf[s]);
                else:
                    metadata[s] = str(self.conf[s]);
        for i in ['connect_start', 'connect_end', 'disconnect_start', 'disconnect_end']:
            if i in self.status:
                self.status[i + '_utc'] = time.strftime("%Y-%m-%dT%H:%M:%S UTC", time.gmtime(self.status[i] / 1000));
        metadata['status'] = self.status;
        with open(os.path.join(self.conf['temp_dir'], self.info['host'] + '.junit.xml'), 'w') as f:
            f.write('\n'.join(x));
        self.conf['junit'] = os.path.join(self.conf['temp_dir'], self.info['host'] + '.junit.xml');
        with open(os.path.join(self.conf['temp_dir'], self.info['host'] + '.meta.yml'), 'w') as f:
            yaml.safe_dump(metadata, f, default_flow_style=False, encoding='utf-8', allow_unicode=True);
        with open(os.path.join(self.conf['temp_dir'], self.info['host'] + '.meta.json'), 'w') as f:
            json.dump(metadata, f, encoding='utf-8', sort_keys=True, indent=4, separators=(',', ': '));
        if self.conf['output_dir'] is not None:
            commit_dir = os.path.join(self.conf['output_dir'], self.info['host']);
            self.conf['data_dir'] = commit_dir;
            if not os.path.exists(commit_dir):
                try:
                    os.makedirs(commit_dir, mode=0700);
                except:
                    self.errors.append('an attempt by ' + self.plugin_name + ' plugin to create output directory for individual hosts failed.');
                    exc_type, exc_value, exc_traceback = sys.exc_info();
                    self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
                    return;
            with open(os.path.join(self.conf['output_dir'], self.info['host'], self.info['host'] + '.junit.xml'), 'w') as f:
                f.write('\n'.join(x));
            self.conf['junit'] = os.path.join(self.conf['output_dir'], self.info['host'], self.info['host'] + '.junit.xml');
            with open(os.path.join(self.conf['output_dir'], self.info['host'], self.info['host'] + '.meta.yml'), 'w') as f:
                yaml.safe_dump(metadata, f, default_flow_style=False, encoding='utf-8', allow_unicode=True);
            with open(os.path.join(self.conf['output_dir'], self.info['host'], self.info['host'] + '.meta.json'), 'w') as f:
                json.dump(metadata, f, encoding='utf-8', sort_keys=True, indent=4, separators=(',', ': '));
        return;


    def _commit(self):
        '''
        This function writes the data collected during this run to
        output directory.
        '''
        if 'output_dir' not in self.conf:
            return;
        if self.conf['output_dir'] is None:
            return;
        commit_dir = os.path.join(self.conf['output_dir'], self.info['host']);
        display.vv('commit directory: ' + commit_dir, host=self.info['host']);
        if not os.path.exists(commit_dir):
            try:
                os.makedirs(commit_dir, mode=0700);
            except:
                self.errors.append('an attempt by ' + self.plugin_name + ' plugin to create global output directory failed.');
                exc_type, exc_value, exc_traceback = sys.exc_info();
                self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
                return;
        if 'cliset' not in self.conf:
            '''
            There were no commands found for this hosts. Nothing to commit.
            '''
            return;
        unique_files = [];
        for _id in self.conf['cliset']:
            if 'path' not in self.conf['cliset'][_id]:
                continue;
            if 'filename' not in self.conf['cliset'][_id]:
                continue;
            if 'sha1' not in self.conf['cliset'][_id]:
                continue;
            if 'status' in self.conf['cliset'][_id]:
                if self.conf['cliset'][_id]['status'] != 'ok':
                    continue;
            if 'preserve' in self.conf['cliset'][_id]:
                if self.conf['cliset'][_id]['preserve'] is False:
                    continue;
            fn = os.path.join(commit_dir, self.conf['cliset'][_id]['filename']);
            if 'sha1' in self.conf['cliset'][_id]:
                if os.path.exists(fn):
                    if os.path.isfile(fn):
                        if os.access(fn, os.R_OK):
                            self.conf['cliset'][_id]['sha1_pre'] = self._get_sha1_hash(fn);
                            if self.conf['cliset'][_id]['sha1_pre'] != self.conf['cliset'][_id]['sha1']:
                                self.info['changed'] = True;
            if fn in unique_files:
                continue;
            else:
                unique_files.append(fn);
            try:
                fc = None;
                with open(self.conf['cliset'][_id]['path'], 'r') as f:
                    fc = f.read();
                fm = 'w';
                fp = os.path.join(commit_dir, self.conf['cliset'][_id]['filename']);
                if 'saveas' in self.conf['cliset'][_id]:
                    fm = 'a';
                    if 'overwrite' in self.conf['cliset'][_id]:
                        if self.conf['cliset'][_id]['overwrite'] is True:
                            fm = 'w';
                    fp = os.path.join(commit_dir, self.conf['cliset'][_id]['saveas']);
                with open(fp, fm) as f:
                    f.write(fc);
                self.conf['cliset'][_id]['path_tmp'] = str(self.conf['cliset'][_id]['path']);
                self.conf['cliset'][_id]['path'] = str(fp);
            except:
                self.errors.append('an attempt by ' + self.plugin_name + ' plugin to save files in its output directory failed.');
                exc_type, exc_value, exc_traceback = sys.exc_info();
                self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
                return;
        return;


    @staticmethod
    def _get_sha1_hash(fn):
        with open(fn, 'rb') as f:
            return hashlib.sha1(f.read()).hexdigest();


    @staticmethod
    def _normalize_str(cmd, host=None, suffix=None):
        if host is not None and suffix is not None:
            cmd = cmd.replace('_', '_US_');
        cmd = cmd.replace('/', '_FS_').replace('|', '_PIPE_').replace('.', '_DOT_').replace(' ', '.');
        cmd = cmd.replace(':', '_CL_').replace(';', '_SCL_').replace('@', '_ATS_').replace('?', '_QM_');
        cmd = cmd.replace('"', '_DQ_').replace('$', '_DLR_');
        if host is None or suffix is None:
            return cmd;
        cmd = host + '.' + cmd + '.' + suffix;
        return cmd;

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
    def _is_dir_empty(fn):
        for dirpath, dirnames, files in os.walk(os.path.expanduser(fn)):
            if len(files) > 0:
                return False;
            else:
                return True;
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

