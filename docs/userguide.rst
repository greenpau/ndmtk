.. index::
   single: User Guide

==========
User Guide
==========

.. include:: localtoc.rst


Please note that the plugin always collects version and configuration
information when mining for network data.


Prerequisites
-------------

The plugin requires the presence of two binaries:

* ``ssh``
* ``expect``

The users of the plugin should know `YAML <http://yaml.org/>`__.,
because it is the toolkit's abstraction format.

The toolkit works on Linux. However, it could work on Windows too.
If you are interested in Windows support, please open an issue.

|Back to Top|_ `Back to Top`_

Builtin Commands
----------------

This plugin uses the following approach when determining which commands are
availble to run on a remote device.

- First, each device must carry ``ndmtk_os`` or ``os`` attribute. Based on
  the value ofthe attribute, the plugin performs a lookup in ``files/cli/os/``
  directory the plugin's directory inside Python's ``site-packages`` directory.
  For example, Cisco ASA firewall must have either ``ndmtk_os=cisco_asa`` or
  ``os-cisco_asa`` attribute.

- Then, the plugin will try to locate ``files/cli/os/cisco_asa.yml`` file. Once
  located, the plugin will read it and collect all of the cli commands
  associated with Cisco ASA operating system.

Please note, based on the information, the plugin will also record which
commands show configuration and version information, and which commands should
be used to disable paging or switch to automation mode.

The ``disable_defaults`` option isables default pre-packages commands for various
operating systems. It is commonly used when configuring a device, as opposed to
gathering data of a device.

|Back to Top|_ `Back to Top`_

User-Defined Commands
---------------------

Per Operating System
^^^^^^^^^^^^^^^^^^^^

The ``cliset_os_dir`` points to the path to YAML files containing user-defined
commands on per operating system basis. The plugin will run the commands only
if the plugin is able to locate a file matching a remote host's operating
system in this directory.

For example, if a host's operating system is ``cisco_nxos``, the plugin
will look for ``cisco_nxos.yml`` file in this directory. If the file is
found, then the plugin will run the commands it found in the file.

Please note that the plugin runs the commands in addition to any default
commands, unless they are disabled with ``disable_defaults``.

The default commands for various operating systems are located
in ``<python_site_packages>/ndmtk/files/cli/os`` directory.

|Back to Top|_ `Back to Top`_

Per Individual Host
^^^^^^^^^^^^^^^^^^^

The ``cliset_host_dir`` points to the path to YAML files containing
user-defined commands on per host basis. The plugin will run the commands
only if the plugin is able to locate a file matching a remote host's
hostname in this directory.

For example, if a host's hostname is ``ny-fw01``, the plugin will look for
``ny-fw01.yml`` file in this directory. If the file is present and readable,
then the plugin will run the commands it finds in the file.

Please note that the plugin runs the commands in addition to any default
commands, unless they are disabled with ``disable_defaults``.

|Back to Top|_ `Back to Top`_

Specific Tasks
^^^^^^^^^^^^^^

Frequently, there is a need to run a specific set of commands for non-data
collection purposes, e.g. device configuration. The ``cliset_spec`` points
to the path to a single YAML file containing user-defined commands.

As with the previously discussed user-defined commands, the plugin runs the
in addition to any default commands, unless they are disabled with
``disable_defaults``.

|Back to Top|_ `Back to Top`_

Exceptions
----------

The ``cliset_exc`` points the path to a single YAML file containing
exceptions to both default and user-defined commands. The root element
of the YAML data structure is ``exceptions``. The structure is a list of
dictionaries/items. Each dictionary item must have at least one of the keys:
``cli``, ``host``, and/or ``os``. The keys are strings containing regular
expressions.

The plugin pre-checks each of the commands it has in its queue against the
exceptions. If the plugin matches a command with the ``cli`` regular expression,
it performs additional ``host`` and ``os`` regular expression searches, if any.
If the plugin is able to match all regular expressions within a single exception,
it marks the command as ``skipped`` and never runs it on the actual device.
By default, the plugin search for
``<ansible_inventory_dir>/files/ndmtk/exceptions.yml`` file.

|Back to Top|_ `Back to Top`_

Limits
------

A user may limit a scope of the commands from any command line set it supplies
to the plugin. The user could use ``sections`` option.

For example, if a user wants to run only BGP-related commands on a device, the
user would add the following to a task ``sections="bgp"``. This way, the
plugin will only execute the commands that have ``bgp`` tag attached to them.

|Back to Top|_ `Back to Top`_

Data Repository
---------------

The plugin uses the value supplied with ``output`` option to determine where
to store the data produced by the plugin. If a path contains ``%`` sign in it,
then the plugin performs pre-defined conversions. For example, ``%h`` is
converted to a host's hostname, ``%H`` to a host's FQDN, and ``%E`` to epoch
timestamp. Please search the plugin's source code for the full list of
converted characters.

.. code-block:: py

            'h': 'hostname',
            'p': 'unique_process_id',
            'U': os.path.split(os.path.expanduser('~'))[-1],
            'Y': str(ts.tm_year).zfill(4),
            'm': str(ts.tm_mon).zfill(2),
            'd': str(ts.tm_mday).zfill(2),
            'H': str(ts.tm_hour).zfill(2),
            'M': str(ts.tm_min).zfill(2),
            'S': str(ts.tm_sec).zfill(2),
            'E': str(int(epoch)),


|Back to Top|_ `Back to Top`_

Security
--------

SSH Fingerprints
^^^^^^^^^^^^^^^^

If the ``no_host_key_check`` option is set to ``yes``, it instructs the
plugin to accept SSH fingerprints without validation, i.e. trust any SSH
fingerprint.

|Back to Top|_ `Back to Top`_

Jumphosts
^^^^^^^^^

The ``jumphosts`` instructs the plugin to access devices via a chain of
jumphosts. In enterprise networks, access to network devices is allowed
only from restricted management stations/hosts. This option allows users
to run tasks through these hosts.

|Back to Top|_ `Back to Top`_

Multi-Factor Authentication (MFA)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Recently, enterprise technology users have been moving to multi-factor
authentication (MFA). It presents a challenge to network automation. However,
with ``token_bypass`` option pointing to the socket of the process with
the knowledge iof what that second (multi) factor is, it is no longer an
issue.

|Back to Top|_ `Back to Top`_

Examples
--------

The following command instructs Ansible to login to ``ny-fw01`` and
collect running configuration from it.

.. code-block:: shell

   ansible-playbook playbooks/collect_configuration.yml

Alternatively, a user may collect the output of all relevant operating
system commands:

.. code-block:: shell

   ansible-playbook playbooks/collect_all.yml

Additionally, this plugin supports Check Mode ("Dry Mode"). In this mode,
the plugin will not attempt to login to network devices. This mode is used
to test for the existence of access credentials.

.. code-block:: shell

   ansible-playbook playbooks/collect_configuration.yml --check

Another way to use the plugin is to configure network devices. The below
Ansible playbook configures ACL on a Cisco ASA firewall.

.. code-block:: shell

   ansible-playbook playbooks/configure_acl.yml --check -vvv
   ansible-playbook playbooks/configure_acl.yml --vvv

This playbook shows how to collecte data via the chaing of devices, i.e
``controller`` => ``10.1.1.1``, ``10.1.1.1`` => ``10.1.2.3``, ``10.1.2.3`` => ``10.2.3.4`` => ``managed node``.

.. code-block:: yaml

   - name: data collection via jumphosts
     action: |
        ndmtk output="/tmp/jump-data-%Y%m%d%H%M%S"
        jumphosts="10.1.1.1,10.1.2.3,10.2.3.4"
        no_host_key_check=yes

|Back to Top|_ `Back to Top`_

Common Errors
-------------

A user may receive the following error:

.. code-block:: shell

   fatal: [ny-fw01]: FAILED! => {
       "failed": true,
       "msg": "The module ndmtk was not found in configured module paths.
               Additionally, core modules are missing.
               If this is a checkout, run 'git submodule update --init --recursive'
               to correct this problem."
   }

This is the indication that something is broken with `setup.py`.
The issue maybe caused by the lack of permissions.
Please open an issue.

|Back to Top|_ `Back to Top`_
