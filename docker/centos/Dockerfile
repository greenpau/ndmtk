FROM centos:latest
MAINTAINER Paul Greenberg @greenpau

RUN yum -y update && yum -y install curl git gcc vim make python-devel libffi-devel openssl-devel && \
    curl -s https://bootstrap.pypa.io/get-pip.py -o get-pip.py && python get-pip.py

RUN pip install --upgrade pip
RUN pip install ansible==2.2.0.0

WORKDIR /etc/ansible

COPY demo/firewall/ansible.vault.yml /root/.ansible.vault.yml
COPY demo/firewall/ansible.vault.key /root/.ansible.vault.key
COPY demo/firewall/hosts /etc/ansible/
COPY demo/firewall/ansible.cfg /etc/ansible/
COPY demo/firewall/README.md /etc/ansible/
COPY demo/firewall/playbooks/*.yml /etc/ansible/playbooks/
COPY demo/firewall/files/ndmtk/spec/*.yml /etc/ansible/files/ndmtk/spec/
COPY demo/firewall/files/ndmtk/os/*.yml /etc/ansible/files/ndmtk/os/
COPY demo/firewall/files/ndmtk/host/*.yml /etc/ansible/files/ndmtk/host/
COPY demo/firewall/files/ndmtk/exceptions.yml /etc/ansible/files/ndmtk/
COPY dist/ndmtk-0.2.0.tar.gz /usr/local/src/
RUN  pip install /usr/local/src/ndmtk-0.2.0.tar.gz

ENTRYPOINT ["/bin/bash"]
