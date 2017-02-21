# Git for Network Discovery and Management Toolkit

This tool is a part of [Network Discovery and Management Toolkit](https://github.com/greenpau/ndmtk).
It allows checking the data collected from network devices in to a Git repository.

The key points relates to the use of the tool:
- The collected data comes in a form of file. The tool commits a file at a time.
- The commit subject is formatted as `<device> [<status>] <cli_commnand>`, e.g.
  `ny-fw01 [ok] show running-config`.
- The commit body contains all the metadata associated with a particular
  cli command.

The tool requires [GitPython](http://gitpython.readthedocs.io).

```
pip install gitpython --user
```

## Getting Started

First, create and initialize a repository:

```
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

```
ndmtk-git -r /opt/ndmtk-data -b master -d /tmp/runner-data -l 1 --commit
```

