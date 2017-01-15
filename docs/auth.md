[![GitHub version](https://badge.fury.io/gh/greenpau%2Fndmtk.svg)](https://badge.fury.io/gh/greenpau%2Fndmtk)
[![CircleCI](https://circleci.com/gh/greenpau/ndmtk.svg?style=svg)](https://circleci.com/gh/greenpau/ndmtk)
[![PyPI version](https://badge.fury.io/py/ndmtk.png)](https://badge.fury.io/py/ndmtk)
[![Documentation Status](https://readthedocs.org/projects/ndmtk/badge/?version=latest)](http://ndmtk.readthedocs.io/)
# Access Credentials Management

This page explains how the toolkit manages network access credentials.

## Ansible Vault

This plugin handles user authentication by way of using user credentials
located in Ansible Vault files. By default, the plugin looks up user
credentials in `~/.ansible.vault.yml` file. The `safe` option points to
the default location of the file.

A user creates the file by running
`ansible-vault create ~/.ansible.vault.yml` command. Upon the creation
of the file, the Ansible Vault prompts the user of a password. This
password is used to decrypt the content of the vault.

The encrypted file is a plain text file. The first line of the file
contains a header. The header specifies the version of Ansible Vault,
encryption type, and looks like this.

``` {.sourceCode .text}
$ANSIBLE_VAULT;1.1;AES256
```

A user edits the file with `ansible-vault edit ~/.ansible.vault.yml`
command.

A user may save the password to unlock the vault in
`~/.ansible.vault.key` file. By default, the plugin uses `lockpick`
option to determine the location of the file unlocking the vault.

For example, the below instruction tells the plugin that the password
for the vault is located in `/opt/admin/unlock.key`. The authentication
credentials for the task are located in `/opt/admin/auth.yml`.

``` {.sourceCode .yaml}
- name: collect data from network nodes
  action: ndmtk output="/tmp/data" safe="/opt/admin/auth.yml" lockpick="/opt/admin/unlock.key"
```

:arrow_up: [Back to top](#top)

*****

## Credentials Structure and Format

The expected way to store access credentials is in YAML format. The data
structure used is a list of hashes, where each hash represents a single
credentials set.

Each hash in the list contains a subset of the following fields:

-   `regex` (regular expression): if the regular expression in this
    field in a hash matches the FQDN or short name of a device, then the
    hash is preferred over any any other hash having the same or higher
    priority. However, if there is no match, then the hash is not used.
-   `priority` (numeric): the field prioritizes the use of credentials.
    The entry with lower priority is preferred over the entry with
    higher priority when multiple entries match a regular expression
    pattern.
-   `default` (boolean): if this field is present and it is set to yes,
    then this credential will be used in the absense of a regex match.
-   `description` (text, optional): it provides an explanation about an
    entry.
-   `username`
-   `password`
-   `enable`: this credential is used when prompted to provide enable
    password. currently, there is no distinction between enable levels.

In the below example a user entered two sets of credentials. The first
entry is used for a specific device, i.e. `ny-fw01`. The second entry is
used by default when there is no regular expression matching network
device host name.

``` {.sourceCode .yaml}
---
credentials:
- regex: ny-fw01
  username: admin
  password: 'NX23nKz!'
  password_enable: '3nKz!NX2'
  priority: 1
  description: NY-FW01 password
- default: yes
  username: greenpau
  password: 'My#DefaultPass'
  password_enable: 'Enabled#By$Default'
  priority: 1
  description: my default password
```

Considerations:

-   There should be no `default` credential with the same `priority`
    level.
-   There should be no credential with both `regex` and `default` fields
    present

:arrow_up: [Back to top](#top)
