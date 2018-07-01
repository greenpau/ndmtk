#
# ndmtk - Network Discovery and Management Toolkit
# Copyright (C) 2016 Paul Greenberg @greenpau
# See LICENSE.txt for licensing details
#
# File: setup.py
#

from __future__ import print_function;

try:
    from setuptools import setup;
except ImportError:
    from ez_setup import use_setuptools;
    use_setuptools();

from setuptools.command.install import install;
from setuptools.command.sdist import sdist;
from setuptools.command.test import test;
from setuptools.command.develop import develop;
from setuptools import setup;
from codecs import open;
import traceback;
import unittest;
import os;
import sys;
import re;
import stat;

import unittest;

pkg_name = 'ndmtk';
pkg_ver = '0.2.0';

cmdclass = {};

def _load_test_suite():
    test_loader = unittest.TestLoader();
    test_suite = test_loader.discover(os.path.join(pkg_dir, pkg_name, 'tests'), pattern='test_*.py');
    return test_suite;

def remove_ansible_files(ansible_dirs):
    for ansible_dir in ansible_dirs:
        for suffix in ['.py', '.pyc']:
            for plugin_type in ['plugins/action', 'plugins/callback']:
                plugin_file = os.path.join(ansible_dir, plugin_type , pkg_name + suffix);
                if os.path.isfile(plugin_file) or os.path.islink(plugin_file):
                    print("[INFO] found '%s'" % plugin_file);
                    try:
                        if os.path.islink(plugin_file):
                            os.unlink(plugin_file);
                        else:
                            os.remove(plugin_file);
                        print("[INFO] removed '%s'" % plugin_file);
                    except:
                        exc_type, exc_value, exc_traceback = sys.exc_info();
                        print("[ERROR] failed to remove %s %s" % (plugin_file, ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))));
    return

def pre_build_toolkit():
    for ts in _load_test_suite():
        tsr=unittest.TextTestRunner();
        tr = tsr.run(ts);
        if len(tr.failures) > 0:
            for tf in tr.failures:
                print('[ERROR] ' + str(tf[1]));
                return [];
    print("[INFO] checking whether 'ansible' python package is installed ...");
    ansible_dirs = _find_py_package('ansible');
    if len(ansible_dirs) == 0:
        print("[ERROR] 'ansible' python package was not found");
        return [];
    print("[INFO] the path to 'ansible' python package is: " + str(ansible_dirs));
    remove_ansible_files(ansible_dirs);
    return ansible_dirs;

def _find_utility(name):
    x = any(os.access(os.path.join(path, name), os.X_OK) for path in os.environ["PATH"].split(os.pathsep));
    return x;

def _find_py_package(name):
    pkg_dirs = [];
    for path in sys.path:
        if not re.search('site-packages$', path):
            continue;
        if not os.path.exists(path):
            continue;
        if not os.path.isdir(path):
            continue
        target = os.path.join(path, name);
        if not os.path.exists(target):
            continue;
        if not os.path.isdir(target):
            continue;
        if target not in pkg_dirs:
            pkg_dirs.append(target);
    return pkg_dirs;

def _post_build_toolkit(ansible_dirs, plugin_dir=None):
    if plugin_dir is None:
        plugin_dirs = _find_py_package(pkg_name);
        if len(plugin_dirs) > 0:
            print("[INFO] the path to '" + pkg_name + "' python package is: " + str(plugin_dirs));
            for d in plugin_dirs:
                if re.search('bdist', d) or re.search('build', d):
                    continue;
                plugin_dir = d;
                break;
    if plugin_dir is None:
        print("[ERROR] failed to find '" + pkg_name + "' python package, aborting!");
        return;
    if re.search('bdist', plugin_dir) or re.search('build', plugin_dir):
        return;
    if re.search('site-packages.?$', plugin_dir):
        plugin_dir += pkg_name;
    print("[INFO] the path to '" + pkg_name + "' python package is: " + str(plugin_dir));
    '''
    Create a symlink, i.e. `ln -s TARGET LINK_NAME`
    '''
    _egg_files = [];
    for ansible_dir in ansible_dirs:
        for i in ['action', 'callback']:
            symlink_target = os.path.join(plugin_dir, 'plugins/' + i + '/ndmtk.py');
            symlink_name = os.path.join(ansible_dir, 'plugins/' + i + '/ndmtk.py');
            try:
                os.symlink(symlink_target, symlink_name);
                os.chmod(symlink_name, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH);
                _egg_files.append(symlink_name);
                _egg_files.append(symlink_name + 'c');
                print("[INFO] created symlink '" + symlink_name + "' to plugin '" + symlink_target + "'");
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info();
                print('[ERROR] an attempt to create a symlink ' + symlink_name + ' to plugin ' + symlink_target + ' failed, aborting!');
                print(traceback.format_exception(exc_type, exc_value, exc_traceback));
    return;

class install_(install):
    def run(self):
        ansible_dirs = pre_build_toolkit();
        if len(ansible_dirs) == 0:
            return 1;
        install.run(self);
        if len(ansible_dirs) > 0:
            self.execute(_post_build_toolkit, (ansible_dirs, self.install_lib, ), msg="running post_install_scripts");

cmdclass['install'] = install_;
cmdclass['bdist_wheel'] = install_;

class uninstall_(develop):
    def run(self):
        plugin_dirs = [];
        for dp in sys.path:
            if not re.search('site-packages$', dp):
                continue;
            ds = [name for name in os.listdir(dp) if os.path.isdir(os.path.join(dp, name))];
            if ds:
                for d in ds:
                    if not re.match(pkg_name, d):
                        continue;
                    if os.path.join(dp, d) not in plugin_dirs:
                        plugin_dirs.append(os.path.join(dp, d));
        if plugin_dirs:
            for dp in plugin_dirs:
                try:
                    for root, dirs, files in os.walk(dp, topdown=False):
                        for name in files:
                            if os.path.islink(os.path.join(root, name)):
                                os.unlink(os.path.join(root, name));
                            else:
                                os.remove(os.path.join(root, name));
                        for name in dirs:
                            os.rmdir(os.path.join(root, name));
                    os.rmdir(dp);
                    print("[INFO] deleted '" + dp + "'");
                except:
                    print("[INFO] failed to delete '" + dp + "'");
                    exc_type, exc_value, exc_traceback = sys.exc_info();
                    print(traceback.format_exception(exc_type, exc_value, exc_traceback));
        else:
            print("[INFO] no relevant files for the uninstall found, all clean");

        ansible_dirs = _find_py_package('ansible');
        if len(ansible_dirs) == 0:
            print("[ERROR] 'ansible' python package was not found");
            return;
        remove_ansible_files(ansible_dirs);
        return;


cmdclass['uninstall'] = uninstall_;

pkg_dir = os.path.abspath(os.path.dirname(__file__));
pkg_license='OSI Approved :: GNU General Public License v3 or later (GPLv3+)';
pkg_description = 'Network Discovery and Management Toolkit packaged as Ansible Plugin';
pkg_url = 'https://github.com/greenpau/' + pkg_name;
#pkg_download_url = 'http://pypi.python.org/packages/source/' + pkg_name[0] + '/' + pkg_name + '/' + pkg_name + '-' + pkg_ver + '.tar.gz';
pkg_download_url = 'https://github.com/greenpau/ndmtk/archive/master.zip';
pkg_author = 'Paul Greenberg';
pkg_author_email = 'greenpau@outlook.com';
pkg_packages = [pkg_name.lower()];
pkg_requires = ['ansible>=2.0'];
pkg_data=[
    '*.yml',
    '*.j2',
    'tests/*.py',
    'plugins/callback/*.py',
    'plugins/action/*.py',
    'plugins/action/*.j2',
    'plugins/action/*.yml',
    'plugins/action/files/cli/os/*.yml',
    'plugins/action/files/cli/core/*.yml',
    'README.rst',
    'LICENSE.txt',
];
pkg_platforms='any';
pkg_classifiers=[
    'Development Status :: 5 - Production/Stable',
    'Environment :: Console',
    'Intended Audience :: Information Technology',
    'Intended Audience :: System Administrators',
    'Intended Audience :: Telecommunications Industry',
    'License :: ' + pkg_license,
    'Programming Language :: Python',
    'Operating System :: POSIX :: Linux',
    'Topic :: Utilities',
    'Topic :: System :: Networking',
    'Topic :: System :: Networking :: Monitoring',
    'Topic :: System :: Systems Administration',
];
pkg_keywords=[
    'ansible',
    'ansible plugin',
    'network',
    'ssh',
    'telnet',
    'console',
    'automation',
    'network automation',
    'network discovery',
];
pkg_test_suite='setup._load_test_suite';

pkg_long_description=pkg_description;
with open(os.path.join(pkg_dir, pkg_name, 'README.rst'), encoding='utf-8') as f:
    pkg_long_description = f.read();

setup(
    name=pkg_name,
    version=pkg_ver,
    description=pkg_description,
    long_description=pkg_long_description,
    url=pkg_url,
    download_url=pkg_download_url,
    author=pkg_author,
    author_email=pkg_author_email,
    license=pkg_license,
    platforms=pkg_platforms,
    classifiers=pkg_classifiers,
    packages=pkg_packages,
    package_data= {
        pkg_name.lower() : pkg_data,
    },
    keywords=pkg_keywords,
    install_requires=pkg_requires,
    test_suite=pkg_test_suite,
    cmdclass=cmdclass
);
