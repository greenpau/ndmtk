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
import hashlib;
import yaml;
import json;
import time;

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
        #else:
        #    self.errors.append('The "' + s  + '" string in "git status " is unsupported.');
        return;

class GitCommitSession(object):

    def __init__(self, **kwargs):
        '''
        Tap into the git repository.
        '''
        self.errors = [];
        self.latest_ts = 0;
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
                    self.repo_dir = dp;
                    logger.debug('Target Repository: ' + self.repo_dir);
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
            self.r = Repo(self.repo_dir);
            self.active_branch = str(self.r.active_branch.name);
            logger.debug('Active Branch: ' + self.active_branch);
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info();
            self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));

        if self.active_branch != self.branch:
            self.errors.append('The active branch of ' + self.repo_dir + ' repository is "' + self.active_branch + '" while "' + self.branch + ' was requested", exiting ...');

        if self.r.is_dirty(untracked_files=True):
            files_arr = str(self.r.git.status(porcelain=True,untracked_files=True)).split('\n');
            self.errors.append('The "' + self.branch + '" branch of "' + self.repo_dir  +  '" repository contains uncommitted or untracked content');
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
        self.summary = {};
        hosts = [];
        hosts_files = {};
        for dp, dns, dfs in os.walk(self.data_dir):
            for fn in dfs:
                fp = os.path.join(dp, fn);
                if re.search('meta.yml$', fp):
                    logger.info('reading execution report from ' + fp);
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
                    output_dir = db['output_dir'];
                    logger.debug('Host: ' + host);
                    logger.debug('FQDN: ' + fqdn);
                    if fqdn not in hosts:
                        hosts.append(fqdn);
                    if fqdn not in hosts_files:
                        hosts_files[fqdn] = [];
                    for cli_rst in db['cli']:
                        if not isinstance(cli_rst, dict):
                            self.errors.append('the "' + fp + '" contains invalid cli metadata (dict):\n' + pprint.pformat(cli_rst));
                            continue;
                        _continue = True;
                        for i in ['path', 'sha1', 'status', '_seq']:
                            if i not in cli_rst:
                                _continue = False;
                                continue;
                            if i == 'path':
                                cli_rst[i] = str(cli_rst[i]).replace(output_dir + '/', '');
                        if not _continue:
                            continue;
                        if cli_rst['status'] != 'ok':
                            continue;
                        _seq = cli_rst['_seq'];
                        if not hasattr(self, 'tasks'):
                            self.tasks = [];
                        task = {
                            'dst_path': os.path.join(self.repo_dir, cli_rst['path']),
                            'src_path': os.path.join(self.data_dir, cli_rst['path']),
                            'host': host,
                            'fqdn': fqdn,
                        }
                        '''
                        `path` is the file pointing to newly collected data.
                        `sha1` is the SHA1 hash of the `path` file.
                        '''
                        for i in cli_rst:
                            if i in ['path_tmp']:
                                continue;
                            if i in task:
                                continue;
                            task[i] = cli_rst[i];
                        
                        if not os.path.exists(os.path.join(self.data_dir, task['src_path'])):
                            logger.error('the source path does not exist: ' + task['src_path']);
                            continue;
                        if not re.match(self.repo_dir, task['dst_path']):
                            '''
                            Temporary files.
                            '''
                            logger.debug('detected reference to tmp file: ' + task['dst_path']);
                            continue;
                        task['sha1'] = self._get_sha1_hash(task['src_path']);
                        if task['sha1'] is None:
                            logger.error('failed to calculate SHA-1 hash for ' + task['src_path']);
                            continue;
                        if os.path.exists(task['dst_path']):
                            task['dst_path_sha1'] = self._get_sha1_hash(task['dst_path']);
                            if task['dst_path_sha1'] is None:
                                logger.error('failed to calculate SHA-1 hash for ' + task['dst_path']);
                                continue;
                        else:
                            logger.info('detected new file: ' + task['src_path']);
                        if task['dst_path'] not in hosts_files[fqdn]:
                            if 'time_start' in task:
                                if int(task['time_start']) > self.latest_ts:
                                    self.latest_ts = int(task['time_start']);
                            hosts_files[fqdn].append(task['dst_path']);
                            _skip_commit = False;
                            if 'dst_path_sha1' in task and 'sha1' in task:
                                if task['sha1'] == task['dst_path_sha1']:
                                    logger.debug('no changes detected in ' + task['dst_path']);
                                    _skip_commit = True;
                            if not _skip_commit:
                                self.tasks.append(task);
                            if fqdn not in self.summary:
                                self.summary[fqdn] = [];
                            summary_task = {};
                            for i in task:
                                if i in ['dst_path', 'src_path', '_seq', 'sha1_pre']:
                                    continue;
                                summary_task[i] = task[i];
                            self.summary[fqdn].append(summary_task);
        '''
        Discover commands that are no longer collected.
        '''
        _break = False;
        for dp, dns, dfs in os.walk(self.repo_dir):
            for fn in dfs:
                if re.search('\.git', dp):
                    continue;
                if re.match('README.md', fn):
                    continue;
                if re.search('meta\.(json|yml)$', fn):
                    continue;
                host = os.path.basename(dp);
                fp = os.path.join(dp, fn);
                if host not in hosts:
                    '''
                    This host was not a part of data collection.
                    '''
                    logger.info('skip ' + host + ' / ' + fp);
                    #self.tasks.append({'mode': 'remove-dir', 'dst_path': fp, 'host': host});
                    continue;
                if fp not in hosts_files[host]:
                    logger.info('removing ' + host + ' / ' + fp);
                    self.tasks.append({'mode': 'remove-file', 'dst_path': fp, 'host': host});
                    continue;
            if _break:
                break;
        return;

    def _commit_file(self, commit_path, commit_msg):
        try:
            self.r.index.add('*');
            files = str(self.r.git.status(porcelain=True,untracked_files=True)).split('\n');
            if len(files) > 1:
                self.errors.append('the number of staged files exceeds the expected value.');
                return;
            gf = GitCommitFile(files[0]);
            if gf.errors:
                self.errors.extend(gf.errors);
                return;
            if not hasattr(gf, 'status_index'):
                return;
            self.r.index.commit('\n'.join(commit_msg), skip_hooks=True);
            logger.info('committed to ' + commit_path);
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info();
            self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
        return;

    def _commit_tasks(self):
        for task in self.tasks:
            dp = os.path.dirname(task['dst_path']);
            fp = task['dst_path'].replace(self.repo_dir, '');
            if not os.path.exists(dp):
                logger.info('path "' + dp + '" does not exist, creating ...');
                try:
                    os.makedirs(dp);
                except OSError as exc:
                    if exc.errno == errno.EEXIST and os.path.isdir(path):
                        pass;
                    else:
                        exc_type, exc_value, exc_traceback = sys.exc_info();
                        self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
                        return;
            if task['mode'] in ['remove-file', 'remove-dir']:
                logger.warning('removing ' + fp);
                commit_msg = 'delete ' + str(fp) + ' from ' + task['host'];
                self.r.index.remove(items=[fp]);
                self.r.index.commit(commit_msg, skip_hooks=True);
                logger.info('removed ' + fp + ' from index');
                try:
                    os.remove(task['dst_path']);
                    logger.info('deleted ' + fp + ' from filesystem');
                except:
                    exc_type, exc_value, exc_traceback = sys.exc_info();
                    self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
            else:
                if 'dst_path_sha1' in task:
                    logger.info('detected changed file: ' +  fp + ' old/new ' + task['dst_path_sha1'] + '/' + task['sha1']);
                else:
                    logger.info('detected new file: ' +  fp + ' ' + task['sha1']);

                with open(task['src_path'], 'r') as fr:
                    with open(task['dst_path'], 'w') as fw:
                        fw.write(fr.read());
                try:
                    self.r.index.add('*');
                    commit_path = task['dst_path'];
                    commit_sbj = task['fqdn'] + ': ';
                    excluded_fields = ['dst_path', 'src_path', 'saveas', 'description', 'sha1_pre', '_seq', 'child_cli_id'];
                    files = str(self.r.git.status(porcelain=True,untracked_files=True)).split('\n');
                    if len(files) > 1:
                        self.errors.append('the number of staged files exceeds the expected value.');
                        return;
                    gf = GitCommitFile(files[0]);
                    if gf.errors:
                        self.errors.extend(gf.errors);
                        return;
                    if not hasattr(gf, 'status_index'):
                        self.errors.append('No status for ' + pprint.pformat(task));
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
                        if field in excluded_fields:
                            continue;
                        commit_msg.append('- `' + field + '`: ' + str(task[field]));
                    self.r.index.commit('\n'.join(commit_msg), skip_hooks=True);
                    logger.info('committed to ' + commit_path);
                except:
                    exc_type, exc_value, exc_traceback = sys.exc_info();
                    self.errors.extend(traceback.format_exception(exc_type, exc_value, exc_traceback));
                    return;
        '''
        Create a summary of changes.
        '''
        for i in self.summary:
            metadata = {'ndmtk_files': self.summary[i]};
            with open(os.path.join(self.repo_dir, i, i + '.meta.yml'), 'w') as f:
                yaml.safe_dump(metadata, f, default_flow_style=False, encoding='utf-8', allow_unicode=True);
            self._commit_file(os.path.join(self.repo_dir, i, i + '.meta.yml'), ['summary for ' + i + ' in YAML format']);
            with open(os.path.join(self.repo_dir, i, i + '.meta.json'), 'w') as f:
                json.dump(metadata, f, encoding='utf-8', sort_keys=True, indent=4, separators=(',', ': '));
            self._commit_file(os.path.join(self.repo_dir, i, i + '.meta.json'), ['summary for ' + i + ' in JSON format']);

    @staticmethod
    def _get_sha1_hash(fn):
        try:
            with open(fn, 'rb') as f:
                return hashlib.sha1(f.read()).hexdigest();
        except:
            return None;

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
    parser.add_argument('--commit', dest='commit', action='store_true',
                            help='commits to repository');
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
    logger.debug(pprint.pformat(gs.tasks));
    if args.commit:
        gs.gmtime = time.gmtime(gs.latest_ts / 1000);
        if len(gs.tasks) > 0:
            gs._commit_tasks();
            if gs.errors:
                _print_errors(gs.errors);
        else:
            logger.warning('all done. there are no pending commits.');
        logger.warning('Once completed, apply tag:');
        logger.warning('   cd ' + gs.repo_dir);
        logger.warning('   git tag -a v' + str(time.strftime("%Y.%m.%d-%H%M", gs.gmtime)) + ' -m \'data collected on ' + str(time.strftime("%Y/%m/%d %H:%M UTC", gs.gmtime))   + '\'');
        logger.warning('   git push');
        logger.warning('   git push --tags');

if __name__ == '__main__':
    main();
