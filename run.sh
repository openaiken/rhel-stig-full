#!/bin/bash
XML_PATH=$HOME/oss/rhel-stig-full/reports ansible-playbook ./play.yml -vv "$@"
