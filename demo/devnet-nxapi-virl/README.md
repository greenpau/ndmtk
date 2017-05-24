# Cisco DevNet Sandbox - NX-API with Nexus 5K

This demo shows how to collect data from [DevNet Sandbox Lab](https://devnetsandbox.cisco.com).
Specifically, NX-API with Nexus 5K.

The lab consists of four (4) NX-OSv switches.

The management addresses reside in 172.16.1.0/24 address space.

The routable address space is 10.0.0.0/24.

## Data Collection

A user collects data by browsing to this directory and invoking a specific
playbook.

```
cd devnet-nxapi-virl/
ansible-playbook playbooks/collect_all.yml -v
```

Once the toolkit collected the data, the user may use `ndmtk-git` to check
that data into source code repository.

## Device Configuration

The following playbook configures OSPF process on the switches.

```
cd devnet-nxapi-virl/
ansible-playbook playbooks/configure_ospf.yml -v
```
