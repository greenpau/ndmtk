# Utilities

These tools are part of [Network Discovery and Management Toolkit](https://github.com/greenpau/ndmtk).

## ndmtk-git: Source Code Control with Git

It allows checking the data collected from network devices in to a Git repository.

The key points relates to the use of the tool:
- The collected data comes in a form of file. The tool commits a file at a time.
- The commit subject is formatted as `<device> [<status>] <cli_commnand>`, e.g.
  `ny-fw01 [ok] show running-config`.
- The commit body contains all the metadata associated with a particular
  cli command.

The tool requires [GitPython](http://gitpython.readthedocs.io).

```bash
pip install gitpython --user
```

### Getting Started

First, create and initialize a repository:

```bash
mkdir -p /opt/ndmtk-data && cd /opt/ndmtk-data && git init
```

Next, run `ndmtk` data collection with the output directory pointing
to `/tmp/runner-data`.

```yaml
---
- name: data collection for git
  hosts:
  - all
  gather_facts: no
  tasks:
  - name: data collection
    action: ndmtk output="/tmp/runner-data" debug=no no_host_key_check=yes on_error=continue
```

Then, run this tool to commit the data in `/tmp/runner-data` to `/opt/ndmtk-data`
Git repository.

```bash
ndmtk-git -r /opt/ndmtk-data -b master -d /tmp/runner-data -l 1 --commit
```

## ndmtk-analytics: Data Mining

It allows to extract structured data from the data collected from network devices.


### Resolve MAC Address Vendors

The following command collects Organizationally Unique Identifier (OUI) data dump:

```
wget -O /opt/ouidb/oui.txt http://standards-oui.ieee.org/oui/oui.txt
```

Next, the data dump can be referenced when retrieving ARP data:

```
ndmtk-analytics -i /opt/ansible-data --arp-entries --csv --mac-vendor-ref /opt/ouidb/oui.txt -o /tmp/arp_entries.csv
```
