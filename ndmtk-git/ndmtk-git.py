#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# ndmtk - Network Discovery and Management Toolkit
# Copyright (C) 2016 Paul Greenberg @greenpau
# See LICENSE.txt for licensing details
#

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os;
import sys;
import re;
import pprint;
import logging;
import argparse;
from collections import OrderedDict;
import traceback;

logging.basicConfig(format='%(asctime)s %(module)s [%(levelname)s] %(message)s');
logger = logging.getLogger(__file__);
logger.setLevel(logging.DEBUG);
toolname = str(os.path.basename(__file__));

try:
    from git import Repo, Commit, Diff;
except:
    logger.error(toolname + ' requires GitPython (gitpython.readthedocs.org), aborting ...');
    sys.exit(1);

try:
    import yaml;
except:
    logger.error(toolname + ' requires PyYAML (http://pyyaml.org/), aborting ...');
    sys.exit(1);

class GitCommitFile(object):
    def __init__(self, s):
        '''
        `status_index` is the status of git staging area.
        `status_worktree` is the status of the files in checkout, i.e. not added to stage.
        '''
        self.errors = [];
        status_codes = {
            'M': 'modified',
            'A': 'added',
            'D': 'deleted',
            'R': 'renamed',
            'C': 'copied',
            'U': 'updated but not merged',
            '?': 'untracked',
            '!': 'ignored',
        }
        self.filename = s;
        m = re.match('^(?P<status>\S{1,2})\s+(?P<filename>.*)', s);
        if m:
            g = m.groupdict();
            for i in g['status']:
                c = str(g['status']);
                if c[0] not in status_codes:
                    self.errors.append('The "' + str(c[0]) + '" index status code is unsupported!');
                else:
                    self.status_code_index = c[0];
                    self.status_index = status_codes[c[0]];
                if len(c) == 2:
                    if c[1] not in status_codes:
                        self.errors.append('The "' + str(c[1]) + '" work tree status code is unsupported!');
                    else:
                        self.status_code_worktree = c[1];
                        self.status_worktree = status_codes[c[1]];
            for p in ['status_index']:
                if not hasattr(self, p):
                    return;
            self.filename = g['filename'];
        else:
            self.errors.append('The "' + s  + '" string in "git status " is unsupported.');
        return;

class GitCommitSession(object):

    def __init__(self, **kwargs):
        '''
        Tap into the git repository.
        '''
        self.errors = [];
        for key, value in kwargs.iteritems():
            if key in ['repo', 'data']:
                dp = os.path.expanduser(value);
                if not os.path.exists(dp):
                    self.errors.append('path ' + str(dp) + ' does not exist');
                    return;
                if not os.path.isdir(dp):
                    self.errors.append('path ' + str(dp) + ' is not a directory');
                    return;
                if not os.access(dp, os.W_OK):
                    self.errors.append('the ' + str(dp) + ' directory is not writable');
                    return;
                if key == 'repo':
                    self.repo = dp;
                    logger.debug('Target Repository: ' + self.repo);
                elif key == 'data':
                    self.data_dir = dp;
                    if not re.search('/$', dp):
                        self.data_dir = dp + '/';
                    logger.debug('Source Data Directory: ' + self.data_dir);
                else:
                    pass;
            elif key == 'branch':
                self.branch = value;
                logger.debug('Target Branch: ' + self.branch);
            else:
                pass;
        try:
            self.r = Repo(self.repo);
            self.active_branch = str(self.r.active_branch.name);
            logger.debug('Active Branch: ' + self.active_branch);
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info();
            self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));

        if self.active_branch != self.branch:
            self.errors.append('The active branch of ' + self.repo + ' repository is "' + self.active_branch + '" while "' + self.branch + ' was requested", exiting ...');

        if self.r.is_dirty(untracked_files=True):
            files_arr = str(self.r.git.status(porcelain=True,untracked_files=True)).split('\n');
            self.errors.append('The "' + self.branch + '" branch of "' + self.repo  +  '" repository contains uncommitted or untracked content');
            files = str(self.r.git.status(porcelain=True,untracked_files=True)).split('\n');
            for f in files:
                gf = GitCommitFile(f);
                if gf.errors:
                    self.errors.extend(gf.errors);
                else:
                    if not hasattr(gf, 'status_worktree'):
                        self.errors.append(' - ' + gf.filename + ' (' + gf.status_index + ')');
                    else:
                        self.errors.append(' - ' + gf.filename + ' (' + gf.status_index + '/' + gf.status_worktree + ')');
        return;


    def _gather_tasks(self):
        for dp, dns, dfs in os.walk(self.data_dir):
            for fn in dfs:
                fp = os.path.join(dp, fn);
                if re.search('meta.yml$', fp):
                    logger.info(fp);
                    db = None;
                    with open(fp, 'r') as fs:
                        try:
                            db = yaml.load(fs);
                        except:
                            exc_type, exc_value, exc_traceback = sys.exc_info();
                            self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
                            continue;
                    if db is None:
                        continue;
                    if not isinstance(db, dict):
                        self.errors.append('the "' + fp + '" is invalid metadata source (yml)');
                        continue;
                    if 'cli' not in db:
                        self.errors.append('the "' + fp + '" is invalid metadata source (cli)');
                        continue;
                    if 'conf' not in db:
                        self.errors.append('the "' + fp + '" is invalid metadata source (conf)');
                        continue;
                    if 'host' not in db['conf']:
                        self.errors.append('the "' + fp + '" is invalid metadata source (conf/host)');
                        continue;
                    if 'fqdn' not in db['conf']:
                        self.errors.append('the "' + fp + '" is invalid metadata source (conf/fqdn)');
                        continue;
                    host = db['conf']['host'];
                    fqdn = db['conf']['fqdn'];
                    logger.debug('Host: ' + host);
                    logger.debug('FQDN: ' + fqdn);
                    for cli_rst in db['cli']:
                        if not isinstance(cli_rst, dict):
                            self.errors.append('the "' + fp + '" contains invalid cli metadata (dict):\n' + pprint.pformat(cli_rst));
                            continue;
                        _continue = True;
                        for i in ['path', 'sha1', 'status', '_seq']:
                            if i not in cli_rst:
                                _continue = False;
                        if not _continue:
                            continue;
                        if cli_rst['status'] != 'ok':
                            continue;
                        _seq = cli_rst['_seq'];
                        if not hasattr(self, 'tasks'):
                            self.tasks = [];
                        task = {
                            'dst_path': os.path.join(self.repo, cli_rst['path'].replace(self.data_dir, '')),
                            'host': host,
                            'fqdn': fqdn,
                        }
                        for i in cli_rst:
                            if i in ['path_tmp']:
                                continue;
                            if i in task:
                                continue;
                            task[i] = cli_rst[i];
                        self.tasks.append(task);
        return;

    def _commit_tasks(self):
        for task in self.tasks:
            dp = os.path.dirname(task['dst_path']);
            if not os.path.exists(dp):
                logger.info('path "' + dp + '" does not exist, creating ...');
                try:
                    os.makedirs(dp);
                except OSError as exc:
                    if exc.errno == errno.EEXIST and os.path.isdir(path):
                        pass
                    else:
                        exc_type, exc_value, exc_traceback = sys.exc_info();
                        self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
                        return;
            if not os.path.exists(task['dst_path']):
                '''
                This is brand new file.
                '''
                with open(task['path'], 'r') as fr:
                    with open(task['dst_path'], 'w') as fw:
                        fw.write(fr.read());
                try:
                    self.r.index.add('*');
                    commit_path = task['dst_path'];
                    commit_sbj = task['fqdn'] + ': ';
                    for field in ['dst_path', 'path', 'saveas', 'description', 'sha1_pre', '_seq', 'child_cli_id']:
                        if field in task:
                            del task[field];
                    files = str(self.r.git.status(porcelain=True,untracked_files=True)).split('\n');
                    if len(files) > 1:
                        self.errors.append('the number of staged files exceeds the expected value.');
                        return;
                    gf = GitCommitFile(files[0]);
                    if gf.errors:
                        self.errors.extend(gf.errors);
                        return;
                    commit_sbj += '[' + gf.status_index + '] ';

                    commit_msg = [];
                    if 'description' in task:
                        commit_sbj += task['description'];
                    else:
                        commit_sbj += task['cli'];
                    commit_msg.append(commit_sbj);
                    commit_msg.append('');
                    commit_msg.append('More info:');
                    for field in sorted(task):
                        commit_msg.append('- `' + field + '`: ' + str(task[field]));
                    self.r.index.commit('\n'.join(commit_msg), skip_hooks=True);
                    logger.info('committed to ' + commit_path);
                except:
                    exc_type, exc_value, exc_traceback = sys.exc_info();
                    self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
                    return;
            else:
                '''
                Calculate the hash of the destination file and if it is
                matches to the source, do nothing.
                '''
                pass;



def _print_errors(x):
    lines = [];
    if isinstance(x, list):
        lines.extend(x);
    elif isinstance(x, str):
        lines.append(x);
    else:
        pass;
    for i in lines:
        for j in i.split('\n'):
            logger.error(j);
    return;


def main():
    """ Main function """
    descr = toolname + ' - git committer for network discovery and management toolkit\n\n'
    epil = '\ngithub: https://github.com/greenpau/ndmtk-git\n\n'
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, \
                                     description=descr, epilog=epil)
    main_group = parser.add_argument_group('arguments')
    main_group.add_argument('-r', '--repo', dest='repo', metavar='REPO', required=True, \
                            type=str, help='Target git repository');
    main_group.add_argument('-b', '--branch', dest='branch', metavar='BRANCH', required=True, \
                            type=str, help='Target git branch');
    main_group.add_argument('-d', '--data', dest='data', metavar='DATA', required=True, \
                            type=str, help='Source data directory');
    parser.add_argument('-l', '--log-level', dest='ilog', metavar='LEVEL', type=int, default=0, \
                        choices=range(1, 3), help='Log level (default: 0, max: 2)');
    args = parser.parse_args();
    if args.ilog == 1:
        logger.setLevel(logging.INFO);
    elif args.ilog == 2:
        logger.setLevel(logging.DEBUG);
    else:
        logger.setLevel(logging.WARNING);
    kwargs = OrderedDict({
        'repo': args.repo,
        'branch': args.branch,
        'data': args.data,
    });
    gs = GitCommitSession(**kwargs);
    if gs.errors:
        _print_errors(gs.errors);
        sys.exit(1);
    gs._gather_tasks();
    if gs.errors:
        _print_errors(gs.errors);
        sys.exit(1);
    if args.ilog > 1:
        if hasattr(gs, 'tasks'):
            for _task in gs.tasks:
                logger.debug('\n' + pprint.pformat(_task));

    gs._commit_tasks();
    if gs.errors:
        _print_errors(gs.errors);

if __name__ == '__main__':
    main();
