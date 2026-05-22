#!/bin/bash
set -e

export XML_PATH=$HOME/oss/rhel-stig-full/reports

ansible-playbook ./formal-role.yml -vv "$@"
ansible-playbook ./cklb.yml -vv "$@"
