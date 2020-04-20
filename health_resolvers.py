#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import os
import sys
import subprocess

check_domain = sys.argv[1]
resolver_file = "temp_resolvers.txt"
health_list = []
tempfile = open("temp_health_resolvers.txt", "a")
with open(resolver_file, "r") as f:
	resolvers = f.read().splitlines()
	for ip in resolvers:
		dig_noerror = len(subprocess.getoutput("dig {} @{} | grep NOERROR".format(check_domain ,ip)))
		test_nxdomain = "sssaberhackxxxnfkjaenrgtio.{}".format(check_domain)
		dig_nxdomain = len(subprocess.getoutput("dig {} @{} | grep NXDOMAIN".format(test_nxdomain ,ip)))
		if dig_noerror > 0 and dig_nxdomain > 0:
			print(ip)
			health_list.append(ip)
			tempfile.writelines(ip + "\n")
tempfile.close()