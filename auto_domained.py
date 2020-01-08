#!/usr/bin/env python3

# #Domain name enumeration tool that leverages awesome tools:
#     - Sublist3r by Ahmed Aboul-Ela (https://github.com/aboul3la/Sublist3r)
#     - enumall by Jason Haddix (https://github.com/jhaddix/domain)
#     - Knock by Gianni Amato (https://github.com/guelfoweb/knock)
#     - Subbrute by TheRook (https://github.com/TheRook/subbrute)
#     - massdns by B. Blechschmidt (https://github.com/blechschmidt/massdns)
#     - Amass by Jeff by Foley (https://github.com/OWASP/Amass)
#     - SubFinder by Ice3man543 (https://github.com/subfinder/subfinder)
#     - Recon-ng by Tim Tomes (LaNMaSteR53) (https://bitbucket.org/LaNMaSteR53/recon-ng)
#     - EyeWitness by ChrisTruncer (https://github.com/FortyNorthSecurity/EyeWitness)
#     - SecList (DNS Recon List) by Daniel Miessler (https://github.com/danielmiessler/SecLists)
#     - LevelUp All.txt Subdomain List by Jason Haddix

# # Github - https://github.com/cakinney (Caleb Kinney)

import argparse
import configparser
import csv
import datetime
import glob
import os
import requests
import smtplib
import time


pastebin_url = "https://pastebin.com/raw/7B2W6bLh"
pastebin_log_file = "pastebin_log"
local_log_file = "local_log"

while 1:
    os.system("wget -O {} {}".format(pastebin_log_file, pastebin_url))
    with open(pastebin_log_file, "r") as f1:
        pastebin_domains = f1.read().splitlines()
    with open(local_log_file, "a+") as f2:
        locallog_domains = f2.read().splitlines()
    for pastebin_domain in pastebin_domains:
        if pastebin_domain not in locallog_domains:
            os.system("python3 domained.py -d {} -p --notify --eyewitness".format(pastebin_domain.split(',')[0]))
            locallog_domains.append(pastebin_domain)
            File_llf = open(local_log_file, "a")
            File_llf.writelines(pastebin_domain+'\n')
            File_llf.close()
            time.sleep(3600)
    time.sleep(3600*24)

