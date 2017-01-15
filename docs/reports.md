[![GitHub version](https://badge.fury.io/gh/greenpau%2Fndmtk.svg)](https://badge.fury.io/gh/greenpau%2Fndmtk)
[![CircleCI](https://circleci.com/gh/greenpau/ndmtk.svg?style=svg)](https://circleci.com/gh/greenpau/ndmtk)
[![PyPI version](https://badge.fury.io/py/ndmtk.png)](https://badge.fury.io/py/ndmtk)
[![Documentation Status](https://readthedocs.org/projects/ndmtk/badge/?version=latest)](http://ndmtk.readthedocs.io/)
# Reports and Structured Data

The important functionality of the toolkit is the ability to produce
reports about data collection process in YAML, JSON, and JUnit formats.

This functionality enables the plugin's integration with Jenkins,
CircleCI, Travis, or any other. Additionally, it provides the ability to
Artificial Intelligence (AI) frameworks to understand what the data is,
without doing any heavy-lifting. In a sense, the structured data
available in the reports becomes an anchor.

:arrow_up: [Back to top](#top)

*****

## JUnit Reporting

The plugin produces reports in JUnit XML format on per host basis.

Each of the JUnit files has the following testsuites:

-   `ndmtk.connect`
-   `ndmtk.execute`
-   `ndmtk.disconnect`

For example, the `ndmtk.connect` testsuite of `ny-sw01` has the
following information. The information is self explanatory. Importanly,
the plugin captures terminal output during connection establishment,
authentication, and authorization.

``` {.sourceCode .xml}
<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
 <testsuite hostname="ny-sw01" name="ndmtk.connect" errors="0" skipped="0" tests="1" failures="0" time="0.41" timestamp="2017-01-15T14:00:20">
  <properties>
   <property name="host" value="ny-sw01"/>
   <property name="os" value="arista_eos"/>
   <property name="output_dir" value="/tmp/test-20170115140020"/>
   <property name="on_error" value="continue"/>
   <property name="on_prompt" value="abort"/>
   <property name="temp_dir" value="/home/greenpau/.ansible/tmp/ndmtk/f3814002-db2a-11e6-87ef-f45c89b1bb39/f3934fe8-db2a-11e6-bffd-f45c89b1bb39/ny-sw01"/>
   <property name="args" value="ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p 8224 -tt admin@localhost"/>
   <property name="play_uuid" value="f3814002-db2a-11e6-87ef-f45c89b1bb39"/>
   <property name="task_uuid" value="f3934fe8-db2a-11e6-bffd-f45c89b1bb39"/>
   <property name="return_code" value="0"/>
   <property name="return_status" value="ok"/>
   <property name="return_msg" value="ok"/>
   <property name="paging_mode" value="configured"/>
   <property name="scripting_mode" value="disabled"/>
   <property name="prompt_mode" value="disabled"/>
   <property name="clisets" value="/lib/python/site-packages/ndmtk/plugins/action/files/cli/os/arista_eos.yml"/>
  </properties>
  <testcase name="connect" status="ok" time="0.41">
   <system_out><![CDATA[
################################################################################
# connection establishment log :
# /home/greenpau/.ansible/tmp/ndmtk/f3814002-db2a-11e6-87ef-f45c89b1bb39/f3934fe8-db2a-11e6-bffd-f45c89b1bb39/ny-sw01/ny-sw01.log_connect
################################################################################

Warning: Permanently added '[localhost]:8224' (ECDSA) to the list of known hosts.
Password:
Last login: Sat Jan 14 15:43:57 2017 from 10.0.2.2
ny-sw01>
ny-sw01#
terminal length 0
Pagination disabled.

]]>
   </system_out>
   <skipped/>
  </testcase>
 </testsuite>
```

The `ndmtk.execute` contains information about the commands executed by
the plugin. Here, the pluging executed `show routing-contex vrf`
command. Then, based on the output, the plugin collected additional
information about default VRF with `show ip route vrf default detail`.

``` {.sourceCode .xml}
<testcase name="Collects default routing context (VRF)" classname="routing, test" status="ok" time="0.371">
 <system_out><![CDATA[
 $ show routing-contex vrf
 |--> $ show ip route vrf default
 |--> $ show ip route vrf default detail

 ]]>
 </system_out>
 <skipped/>
</testcase>
```

:arrow_up: [Back to top](#top)

*****

## Structure Data

The below are snippets from the output of `ny-sw01.meta.yml` file:

Here, after the `show vrf` was successfully executed, the plugin stored
the data in a temporary directory. The output contained six (6) lines.
Based on the output, the plugin captured two follow up commands:

-   `show ip route vrf management`
-   `show ip route vrf management detail`

Next, the command is associated with two tags: `routing`, `vrf`. Based
on the `source` field, the source of the commands is pre-packaged
operating system based rules, i.e. `os_default`.

``` {.sourceCode .yaml}
- _seq: 3
  allow_empty_response: false
  child_cli_id:
  - show ip route vrf management
  - show ip route vrf management detail
  cli: show vrf
  description: Collects VRF information
  format: txt
  lines: '6'
  mode: analytics
  path: /tmp/test-20170115140020/ny-sw01/ny-sw01.show.vrf.txt
  path_tmp: /home/greenpau/.ansible/tmp/ndmtk/f3814002-db2a-11e6-87ef-f45c89b1bb39/f3934fe8-db2a-11e6-bffd-f45c89b1bb39/ny-sw01/ny-sw01.show.vrf.txt
  sha1: 949faac85f41f62566b8609455ad2e67c87e57cb
  source: os_default
  status: ok
  tags:
  - routing
  - vrf
```

Then, there is the `status` field. It provides various information about
the data collection task. Importantly, it has `facts` field. It is
similar to the data produced by `facter` tool from Puppet labs.

``` {.sourceCode .yaml}
status:
  authenticated: 'yes'
  authorized: 'yes'
  clisets:
  - /usr/lib/python/site-packages/ndmtk/plugins/action/files/cli/os/arista_eos.yml
  connect_end: 1484488820999
  connect_end_utc: 2017-01-15T14:00:20 UTC
  connect_start: 1484488820589
  connect_start_utc: 2017-01-15T14:00:20 UTC
  connected: 'yes'
  disconnect_end: 1484488824087
  disconnect_end_utc: 2017-01-15T14:00:24 UTC
  disconnect_start: 1484488824021
  disconnect_start_utc: 2017-01-15T14:00:24 UTC
  disconnected: 'yes'
  facts:
    hardware_macaddr: 0800.2756.4f61
    memory_free: 2891812 kB
    memory_total: 3887680 kB
    os_arch: i386
    os_class: arista_eos
    os_internal_build_id: c6362f13-ae6d-4c88-b5fd-4678d66018ab
    os_internal_build_version: 4.17.2F-3696283.4172F
    os_name: vEOS
    os_vendor: Arista
    os_version_major: '4'
    os_version_minor: '17'
    os_version_patch: 2F
    uptime: 21 hours and 18 minutes
  paging_mode: configured
  prompt_mode: disabled
  return_code: 0
  return_msg: ok
  return_status: ok
  scripting_mode: disabled
  spawned: 'yes'
task_uuid: f3934fe8-db2a-11e6-bffd-f45c89b1bb39
temp_dir: /home/greenpau/.ansible/tmp/ndmtk/f3814002-db2a-11e6-87ef-f45c89b1bb39/f3934fe8-db2a-11e6-bffd-f45c89b1bb39/ny-sw01
```

The plugin uses the `facts` field when processing output through its
Rules Engine.

``` {.sourceCode .yaml}
- description: 'Collects routing table'
  cli: 'show ip route vrf all'
  tags: ['routing']
  conditions_precedent_all:
  - 'os_class eq arista_eos'
  - 'os_version_major ge 5'
```

Here, the `show ip route vrf all` will not run on the device, because
`facts`'s `os_version_major` is less than the `os_version_major` in the
`conditions_precedent_all` for the rule.

If a user wants to run the `show ip route vrf all`, the user should
change `conditions_precedent_all` to:

``` {.sourceCode .yaml}
conditions_precedent_all:
- 'os_class eq arista_eos'
- 'os_version_major ge 4'
```

:arrow_up: [Back to top](#top)

*****

## Status Codes

Upon the completion of a particular command, the plugin updates the
`status` field of the command. The list of possible values follows:

-   `ok`: worked as expected
-   `failed`
-   `skipped`
-   `conditional`: assigned when entered into the database and has
    `conditions_match` or `conditions_precedent_all` field associated
    with a command.
-   `retry`
-   `unknown`: assigned when entered into the database

:arrow_up: [Back to top](#top)
