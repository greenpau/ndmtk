from setuptools import setup;
from setuptools.command.install import install;
from codecs import open;
from os import path;
import unittest;
import os;
import sys;
import re;
import stat;

pkg_name = 'ndmtk';
pkg_ver = '0.1';

def _load_test_suite():
    test_loader = unittest.TestLoader();
    test_suite = test_loader.discover(path.join(pkg_dir, pkg_name, 'tests'), pattern='test_*.py');
    return test_suite;

class InstallAddons(install):
    '''
    Creates custom symlink to ansible site-packages directory
    '''



    def run(self):
        errors = False;
        if not self._find_utility('ssh'):
            print('FAIL: ssh client is not found');
            errors = True;
        if not self._find_utility('expect'):
            print('FAIL: expect utility is not found');
            errors = True;
        if errors:
            print('aborted install');
            return;
        install.run(self);
        '''
        Find current plugin directory
        '''
        ansible_dirs = self._find_py_package('ansible');
        if len(ansible_dirs) == 0:
            print('FAIL: ansible is not found');
            return;
        '''
        Find this plugin's directory
        '''
        plugin_dirs = self._find_py_package(pkg_name);
        if len(plugin_dirs) == 0:
            print('FAIL: ' + pkg_name + ' is not found');
            return;

        '''
        Create a symlink, i.e. `ln -s TARGET LINK_NAME`
        '''
        _errors = [];
        _symlinks = {};
        _id = 0;
        for pdir in plugin_dirs:
            for adir in ansible_dirs:
                for i in ['action', 'callback']:
                    symlink_target = os.path.join(pdir, 'plugins/' + i + '/ndmtk.py');
                    symlink_name = os.path.join(adir, 'plugins/' + i + '/ndmtk.py');
                    try:
                        if os.path.exists(symlink_name):
                            os.unlink(symlink_name);
                        os.symlink(symlink_target, symlink_name);
                        os.chmod(symlink_name, stat.S_IRUSR | stat.S_IWUSR);
                        _symlinks[_id] = {'symlink': symlink_name, 'target': symlink_target};
                        _id += 1;
                    except:
                        _errors.append('an attempt to create a symlink ' + symlink_name + ' to plugin ' + symlink_target + ' failed');
        if len(_errors) > 0:
            for i in _errors:
                print('FAIL: ' + i);
        if len(_symlinks) > 0:
            for i in _symlinks:
                print('SUCCESS: the symlink ' + _symlinks[i]['symlink'] + ' to plugin ' + _symlinks[i]['target'] + ' was created successfully');


    @staticmethod
    def _find_utility(name):
        x = any(os.access(os.path.join(path, name), os.X_OK) for path in os.environ["PATH"].split(os.pathsep));
        return x;

    @staticmethod
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

pkg_dir = path.abspath(path.dirname(__file__));
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
    'plugins/action/files/cli/addons/*.yml',
    'README.rst',
    'LICENSE.txt',
];
pkg_platforms='any';
pkg_classifiers=[
    'Development Status :: 4 - Beta',
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
with open(path.join(pkg_dir, pkg_name, 'README.rst'), encoding='utf-8') as f:
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
    cmdclass={
        'install': InstallAddons,
        'bdist_wheel': InstallAddons,
    },
);
