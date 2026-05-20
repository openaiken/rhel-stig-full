#!/bin/bash
XML_PATH=$HOME/oss/rhel-stig-full/reports/results_$(date +%s).xml ansible-playbook ./play.yml -vv $@
