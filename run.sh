#!/bin/bash
XML_PATH=/home/hayden.aiken/other-playbooks/rhel-stig-full/reports/results_$(date +%s).xml ansible-playbook ./play.yml -vv $@
