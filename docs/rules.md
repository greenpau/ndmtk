[![GitHub version](https://badge.fury.io/gh/greenpau%2Fndmtk.svg)](https://badge.fury.io/gh/greenpau%2Fndmtk)
[![CircleCI](https://circleci.com/gh/greenpau/ndmtk.svg?style=svg)](https://circleci.com/gh/greenpau/ndmtk)
[![PyPI version](https://badge.fury.io/py/ndmtk.png)](https://badge.fury.io/py/ndmtk)
[![Documentation Status](https://readthedocs.org/projects/ndmtk/badge/?version=latest)](http://ndmtk.readthedocs.io/)
# Rules Engine

This page describes the toolkit's rules engine.

## Data Collection Rules

The decision how to collect data from a network device is governed by
the rules engine. It is abstructed in the form of YAML.

### Basic Conditions

The following rule applies to any Linux distribution. The purpose of the
rule is to discover the paths to all binaries in the user's `PATH`
environment variable. The information collected is stored in a reference
database with tags `binaries` and `configuration`.

.. code-block:: yaml

    - description: 'collect the file listing of binaries in PATH'
      cli: 'find \$(env | grep "\^PATH=" | sed "s/PATH=//;s/:/ /g") -maxdepth 10 -type f -print | sed "s/\\/\\//\\//"'
      tags: ['ref:binaries', 'configuration']
      saveas: '%h.files.bin.txt'

Later, we could utilize the references in other rules.

For example, there will be no collection of IP addressing information unless
ifconfig\` binary is present.

``` {.sourceCode .yaml}
- description: 'collect ip addressing information via sysctl'
  cli: 'ifconfig -a'
  tags: ['network']
  conditions_match_any:
  - 'tag:binaries:.*bin/ifconfig$'
```

At the same time, the plugin will collect information if `ip` binary is
present:

``` {.sourceCode .yaml}
- description: 'collect ip routing information'
  cli: 'ip route'
  tags: ['network']
  conditions_match_any:
  - 'tag:binaries:.*bin/ip$'
```

:arrow_up: [Back to top](#top)

*****

### Derivatives

In some cases, it is necessary to run follow up commands to discover
more data.

The below rule instructs the plugin to read kernel network interface
table `/proc/net/dev` and run follow up `ethtool` commands if `ethtool`
is available.

``` {.sourceCode .yaml}
- description: 'collect kernel network interface statistics'
  cli: 'cat /proc/net/dev'
  tags: ['network', 'test']
  saveas: '%h.ifstats.txt'
  derivatives:
  - os:
    - generic_linux
    regex:
    - pattern: '^\s*(?P<IF_NAME>\S+):'
      flags: ['add_cli']
    actions:
    - description: 'collect network interface driver and hardware settings from <IF_NAME>'
      cli:
      - 'ethtool <IF_NAME>'
      - 'ethtool --show-pause <IF_NAME>'
      - 'ethtool --show-coalesce <IF_NAME>'
      - 'ethtool --show-ring <IF_NAME>'
      - 'ethtool --driver <IF_NAME>'
      - 'ethtool --show-features <IF_NAME>'
      - 'ethtool --statistics <IF_NAME>'
      - 'ethtool --show-nfc <IF_NAME>'
      - 'ethtool --show-ntuple <IF_NAME>'
      - 'ethtool --show-eee <IF_NAME>'
      - 'ethtool --show-priv-flags <IF_NAME>'
      - 'ethtool --show-channels <IF_NAME>'
      - 'ethtool --show-time-stamping <IF_NAME>'
      - 'ethtool --show-permaddr <IF_NAME>'
      - 'ethtool --module-info <IF_NAME>'
      - 'ethtool --show-eee <IF_NAME>'
      saveas: '%h.ethtool.<IF_NAME>.txt'
      append: yes
      required: ['IF_NAME']
      conditions_match_all:
      - 'tag:binaries:.*in/ethtool$'
      allow_empty_response: no
```

:arrow_up: [Back to top](#top)

*****

Similarly, the below rule applies to Cisco NX-OS devices. The plugin run
`show ip bgp summary vrf all` on a device only if `router bgp` process
is configured. Once collected, the plugin collects BGP neighborship
information from the output of the command. If the plugin finds a BGP
neighbor, it will collect the `advertised-routes` and `received-routes`
from that neighbor.

``` {.sourceCode .yaml}
- cli: show ip bgp summary vrf all
  tags: ['routing', 'bgp']
  conditions_match_any:
  - '^router bgp'
  derivatives:
  - description: 'BGP neighbor details'
    os:
    - cisco_nxos
    regex:
    - pattern: 'BGP summary information for VRF (?P<VRF>\S+), address family'
      flags: ['purge']
    - pattern: '\s*(?P<IP_ADDRESS>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\d\s+'
      flags: ['add_cli']
    actions:
    - cli: 'show ip bgp neighbors <IP_ADDRESS> vrf <VRF>'
      required: ['IP_ADDRESS', 'VRF']
      format: 'txt'
    - cli: 'show ip bgp neighbors <IP_ADDRESS> advertised-routes vrf <VRF>'
      required: ['IP_ADDRESS', 'VRF']
      format: 'txt'
    - cli: 'show ip bgp neighbors <IP_ADDRESS> received-routes vrf <VRF>'
      required: ['IP_ADDRESS', 'VRF']
      format: 'txt'
```

:arrow_up: [Back to top](#top)

*****

### No Newline

In some cases, there is a need to check the command line options
available to a user. Traditionally, a user would do it with question
mark at the end of the user's request.

Here, the user issues `show service-policy inspect ?` to get available
options. However, when doing so, the user does not press `Enter`. The
`no_newline` field mimic the describes behavior. If the field does not
exist or if it is set to `no`, then the newline character will be
appended to the user's request.

``` {.sourceCode .yaml}
- description: 'Collect a list of all possible inspection policies.'
  cli: 'show service-policy inspect ?'
  no_newline: yes
  os:
  - cisco_asa
  tags: ['inspect', 'test']
  conditions_match_all:
  - '^policy-map\s'
  - '^\s+class\s'
  - '^\s+inspect\s'
  derivatives:
  - description: 'Collects information about individual inspection policies'
    os:
    - cisco_asa
    regex:
    - pattern: '^\s*(?P<INSPECTION_POLICY_NAME>\S+$)\s+Show'
      flags: ['add_cli']
    actions:
    - description: 'Collects statistics for inspect <INSPECTION_POLICY_NAME> policy'
      cli: 'show service-policy inspect <INSPECTION_POLICY_NAME>'
      required: ['INSPECTION_POLICY_NAME']
      format: 'txt'
```

:arrow_up: [Back to top](#top)

*****

### Success and Error Overwrites

One of the derivative `show service-policy inspect` commands produces an
error:

``` {.sourceCode .bash}
show service-policy inspect h323
ERROR: % Incomplete command
```

In order to avoid an error, a user may add `success_if` field. This
causes the plugin to declare the output to be a success, despite that it
is failing.

``` {.sourceCode .yaml}
- description: 'Collects statistics for inspect <INSPECTION_POLICY_NAME> policy'
  cli: 'show service-policy inspect <INSPECTION_POLICY_NAME>'
  required: ['INSPECTION_POLICY_NAME']
  format: 'txt'
  success_if:
  - '.*'
```

:arrow_up: [Back to top](#top)

*****

### Facts

The plugin's configuration files has sections dedicated to fact
discovery based on the outputs related to software and/or hardware
information. For example, CentOS servers have `/etc/os-release` file.

The contents of the file are as follows:

``` {.sourceCode .bash}
NAME="CentOS Linux"
VERSION="7 (Core)"
ID="centos"
ID_LIKE="rhel fedora"
VERSION_ID="7"
PRETTY_NAME="CentOS Linux 7 (Core)"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:centos:centos:7"
HOME_URL="https://www.centos.org/"
BUG_REPORT_URL="https://bugs.centos.org/"

CENTOS_MANTISBT_PROJECT="CentOS-7"
CENTOS_MANTISBT_PROJECT_VERSION="7"
REDHAT_SUPPORT_PRODUCT="centos"
REDHAT_SUPPORT_PRODUCT_VERSION="7"
```

The engine has rules to match against that output:

``` {.sourceCode .yaml}
- pattern: '^NAME="?(?P<os_name>.*)["]?$'
  add:
  - 'os_class=generic_linux'
  strip_quotes: yes
- pattern: '^VERSION_ID="?(?P<os_version>\d+)"?'
  strip_quotes: yes
- pattern: '^ID=(?P<os_subclass>\S+)$'
  strip_quotes: yes
```

Please note the `strip_quotes` key. When plugin discovers its presence,
it strips double quotes from the captured values.

The plugin's analytics engine adds the metadata in the following format:

``` {.sourceCode .yaml}
facts:
  os_class: generic_linux
  os_name: CentOS Linux
  os_subclass: centos
  os_version: '7'
```

:arrow_up: [Back to top](#top)

*****

## Rule Design

Each command executed by the plugin runs in one of the below modes:

-   `noop`
-   `analytics`
-   `configure`
-   `pre`
-   `post`

:arrow_up: [Back to top](#top)

*****

## Condition Precedent

The `condition_precedent_all` is a list of conditions. Each condition in
the list is a string. The string must conform to the following format:
`item predicate value`.

The `item` is what the toolkit will be looking for in `facts`
dictionary.

The `predicate` are the type of a predicate used:

-   `eq`: equals (both numeric and string, unless there is a type
    mismatch)
-   `ne`: equals (both numeric and string, unless there is a type
    mismatch)
-   `ge`: greater or equal (numeric evaluation)
-   `gt`: greater than (numeric evaluation)
-   `lt`: less than (numeric evaluation)
-   `le`: less or equal (numeric evaluation)
-   `rgx`: regular expression evaluation via `match`, as opposed to
    search

The `value` is variable.

:arrow_up: [Back to top](#top)
