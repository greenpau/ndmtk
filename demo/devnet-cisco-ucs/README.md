# Cisco DevNet Sandbox - Meraki API

This demo shows how to collect data from [Meraki API](https://learninglabs.cisco.com/modules/dnc-2017-meraki/meraki-dashboard-api/step/1).

## Data Collection

A user collects data by browsing to this directory and invoking a specific
playbook.

```
cd devnet-meraki/
ansible-playbook playbooks/collect_all.yml -v
```

Once the toolkit collected the data, the user may use `ndmtk-git` to check
that data into source code repository.
