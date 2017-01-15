# Demo Instructions

Review network access credentials in Ansible Vault:

```
ansible-vault edit ~/.ansible.vault.yml --vault-password ~/.ansible.vault.key
```

If necessary, adjust SSH configuration file. For example, the
below firewall does not support latest algorithms. Thus,
the enabling of `diffie-hellman-group1-sha1` is necessary:

```
mkdir -p ~/.ssh
cat <<EOF > ~/.ssh/config
Host 192.168.99.39
    KexAlgorithms +diffie-hellman-group1-sha1
EOF
```

Next, "Dry Run" Ansible playbook:

```
ansible-playbook playbooks/collect_all.yml --check -vvv
```

If the above output looks good, connect to the devices
and collect data:

```
ansible-playbook playbooks/collect_all.yml -v
```
