#
# ndmtk - Network Discovery and Management Toolkit
# Copyright (C) 2016 Paul Greenberg @greenpau
# See LICENSE.txt for licensing details
#
# File: plugins/callback/ndmtk.py
#

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.plugins.callback import CallbackBase;
from ansible.errors import AnsibleError;

try:
    from __main__ import display;
except ImportError:
    from ansible.utils.display import Display;
    display = Display();

import os;
import uuid;
import re;
import pprint;
import traceback;
import time;
from ansible.parsing import vault;
from ansible.parsing.yaml.loader import AnsibleLoader
try:
    from ansible import constants as C;
except:
    pass
from ansible.cli import CLI;
from ansible.parsing.dataloader import DataLoader;

class CallbackModule(CallbackBase):

    '''
    This is an ansible callback plugin that work with only
    `ndmtk` action plugin. The purpose of this plugin
    is generating unique UUIDs for plays and tasks.

    This plugin makes use of the following environment variables:
        HOME              (required): User home directory

    Requires:
        uuid
    '''

    CALLBACK_VERSION = 2.0;
    CALLBACK_TYPE = 'notification';
    CALLBACK_NAME = 'ndmtk';
    CALLBACK_NEEDS_WHITELIST = False;

    def __init__(self):
        super(CallbackModule, self).__init__();

    def playbook_on_play_start(self, name):
        pass;

    def v2_playbook_on_play_start(self, play):
        _action = self.CALLBACK_NAME;
        _trigger = False;
        _tasks_list = play.get_tasks();
        _nodes = [];
        _secrets = [];
        #self._ndmtk_debug = True;
        if isinstance(_tasks_list, list):
            for _task_list in _tasks_list:
                if not isinstance(_task_list, list):
                    continue;
                _safe = None;
                _lockpick = None;
                for _task in _task_list:
                    _task_data = _task.serialize();
                    _safe = None;
                    _lockpick = None;
                    if not isinstance(_task_data, dict):
                        continue;
                    if 'action' in _task_data:
                        if str(_task_data['action']) == _action:
                            _trigger = True;
                            if 'args' in _task_data:
                                if 'debug' in _task_data['args']:
                                    if re.match('^(y|yes|true|1)$', str(_task_data['args']['debug']).strip(), flags=re.IGNORECASE):
                                        self._ndmtk_debug = True;
                                if 'jumphosts' in _task_data['args']:
                                    for h in str(_task_data['args']['jumphosts']).split(","):
                                        j = h.split(":")[0];
                                        if j not in _nodes:
                                            _nodes.append(j);
                                if 'safe' in _task_data['args']:
                                    _safe = str(_task_data['args']['safe']);
                                if 'lockpick' in _task_data['args']:
                                    _lockpick = str(_task_data['args']['lockpick']);
                    if not _safe:
                        _safe = "~/.ansible.vault.yml";
                    if not _lockpick:
                        _lockpick = "~/.ansible.vault.key";
                    if (_safe, _lockpick) not in _secrets:
                        _secrets.append((_safe, _lockpick));
        if _trigger:
            _user_home = None;
            for i in ('HOME', 'USERPROFILE', 'HOMEDRIVE'):
                if i in ['HOME', 'USERPROFILE']:
                    if i in os.environ:
                        _user_home = str(os.environ[i]);
                        break;
                elif  i in ['HOMEDRIVE']:
                    if 'HOMEDRIVE' in os.environ and 'HOMEPATH' in os.environ:
                        _user_home = str(os.path.join(os.environ['HOMEDRIVE'], os.environ['HOMEPATH']));
                        break;
                else:
                    pass;
            if not _user_home:
                raise AnsibleError("failed to determine user's home directory");
            self._ndmtk_play_uuid = str(uuid.uuid1());
            try:
                (head, tail) = os.path.split(C.DEFAULT_LOCAL_TMP)
                self._ndmtk_user_home = os.path.join(head, self.CALLBACK_NAME)
            except:
                self._ndmtk_user_home = os.path.join(_user_home, '.ansible', 'tmp', self.CALLBACK_NAME);
            self._ndmtk_dirs = [];
            '''
            Retrieve authentication credentials.
            '''
            _play_data = play.serialize();
            if 'hosts' in _play_data:
                if isinstance(_play_data['hosts'], list):
                    _nodes.extend(_play_data['hosts']);
            self._ndmtk_secrets = self._load_auth_secrets(_nodes, _secrets);
            if hasattr(self, '_ndmtk_debug'):
                if self._ndmtk_debug:
                    _play_tmpdir = os.path.join(self._ndmtk_user_home, str(self._ndmtk_play_uuid));
                    display.display('temporary playbook directory: "' + _play_tmpdir + '" directory', color='yellow');
                    display.display("play data:\n" + pprint.pformat(_play_data, indent=4), color='yellow');
            _play_tmpdir = os.path.join(self._ndmtk_user_home, str(self._ndmtk_play_uuid));
            display.display('<ndmtk> temporary directory: "' + _play_tmpdir + '" directory', color='green');
        pass;

    def playbook_on_task_start(self, name, conditional):
        pass;

    def v2_playbook_on_task_start(self, task, is_conditional):
        if hasattr(self, '_ndmtk_play_uuid'):
            task.args['play_uuid'] =  str(self._ndmtk_play_uuid);
            task.args['task_uuid'] = str(uuid.uuid1());
            if hasattr(self, '_ndmtk_secrets'):
                task.args['credentials'] = self._ndmtk_secrets;
            _task_tmpdir = os.path.join(self._ndmtk_user_home, task.args['play_uuid'], task.args['task_uuid']);
            _task_data = task.serialize();
            if 'args' in _task_data:
                for i in ['output', 'output_dir']:
                    if i in _task_data['args']:
                        self._ndmtk_output_dir = self._decode_ref(_task_data['args'][i], task.args['play_uuid'], task.args['task_uuid']);
                        task.args[i] = str(self._ndmtk_output_dir);
                        break;
            if hasattr(self, '_ndmtk_debug'):
                if self._ndmtk_debug:
                    display.display('temporary task directory: "' + _task_tmpdir + '" directory', color='yellow');
                    _task_data = task.serialize();
                    display.display("task data:\n" + pprint.pformat(_task_data, indent=4), color='yellow');
        pass;

    def _load_auth_secrets(self, hosts=[], secrets=[]):
        for _safe, _lockpick in secrets:
            try:
                _safe_loader = DataLoader();
                _safe_lockpick = None
                try:
                    _safe_lockpick = CLI.read_vault_password_file(_lockpick, loader=_safe_loader);
                    _safe_loader.set_vault_password(_safe_lockpick);
                    _safe_contents = _safe_loader.load_from_file(_safe);
                except:
                    _safe_lockpick = CLI.setup_vault_secrets(_safe_loader, [_lockpick])
                    _safe_contents = _safe_loader.load_from_file(_safe);
                if 'credentials' not in _safe_contents:
                    return dict();
                #display.display(pprint.pformat(_safe_contents, indent=4), color='green');
                return _safe_contents['credentials'];
            except Exception as e:
                display.display('[ERROR] ' + str(e), color='red');
        return dict();

    def v2_playbook_on_stats(self, stats):
        ''' Display info about playbook statistics '''
        if hasattr(self, '_ndmtk_output_dir'):
            display.display('<ndmtk> output directory: ' + self._ndmtk_output_dir, color='green');

    def _decode_ref(self, s, play_uuid, task_uuid):
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
        epoch = time.time();
        ts = time.gmtime(epoch);
        self.refs = {
            'P': play_uuid,
            'p': task_uuid,
            'U': os.path.split(os.path.expanduser('~'))[-1],
            'Y': str(ts.tm_year).zfill(4),
            'm': str(ts.tm_mon).zfill(2),
            'd': str(ts.tm_mday).zfill(2),
            'H': str(ts.tm_hour).zfill(2),
            'M': str(ts.tm_min).zfill(2),
            'S': str(ts.tm_sec).zfill(2),
            'E': str(int(epoch)),
        };
        for i in self.refs:
            s = s.replace('%' + i, self.refs[i]);
        return s;
