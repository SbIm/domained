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
import subprocess
import pdb
from signal import signal, alarm, SIGALRM
from installer import upgradeFiles
from installer import refreshResolvers
from shutil import which


today = datetime.date.today()
wildList = []
cnameWildList = []
NOWILD = 0
AWILD = 1
CNAMEWILD = 2


altdnsWildList = []

def get_args():
    parser = argparse.ArgumentParser(description="domained")
    parser.add_argument(
        "-d", "--domain", type=str, help="Domain", required=False, default=False
    )
    parser.add_argument(
        "-s",
        "--secure",
        help="Secure",
        action="store_true",
        required=False,
        default=False,
    )
    parser.add_argument(
        "-b", "--bruteforce", help="Bruceforce", action="store_true", default=False
    )
    parser.add_argument("--upgrade", help="Upgrade", action="store_true", default=False)
    parser.add_argument("--install", help="Install", action="store_true", default=False)
    parser.add_argument("--vpn", help="VPN Check", action="store_true", default=False)
    parser.add_argument(
        "-p", "--ports", help="Ports", action="store_true", default=False
    )
    parser.add_argument(
        "-q", "--quick", help="Quick", action="store_true", default=False
    )
    parser.add_argument(
        "--bruteall", help="Bruteforce JHaddix All", action="store_true", default=False
    )
    parser.add_argument(
        "--fresh", help="Refresh resolvers", action="store_true", default=False
    )
    parser.add_argument(
        "--notify", help="Notify when script completed", action="store_true", default=False
    )
    parser.add_argument(
        "--active", help="EyeWitness Active Scan", action="store_true", default=False
    )
    parser.add_argument(
        "--eyewitness", help="Use EyeWitness", action="store_true", default=False
    )

    return parser.parse_args()


newpath = r"output"
if not os.path.exists(newpath):
    os.makedirs(newpath)

def altdns():
    # global altdnsWildList
    print("\n\n\033[1;31mRunning altdns \n\033[1;37m")
    word_file = os.path.join(
        script_path, "bin/altdns/words.txt"
    )
    altdnsCMD = "altdns -i {} -o {} -w {}".format(
        "{}_massdns_noaltdns_strip.txt".format(output_base),
        "{}-altdns-data".format(output_base),
        word_file,
    )
    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(altdnsCMD))
    os.system(altdnsCMD)
    print("\n\033[1;31mAltdns Complete\033[1;37m")
    time.sleep(1)
    with open("{}-altdns-data".format(output_base), "r") as f:
        altdnsData = f.read().splitlines()
    with open("altdnsTemp", "a") as altf:
        for altdnsLine in altdnsData:
            altf.writelines(altdnsLine + "\n")
            altdnsLine = altdnsLine.split(".", 1)[1]
            altdnsLine = "xxfeedcafejfoiaeowjnbnmcoampqoqp." + altdnsLine
            altf.writelines(altdnsLine + "\n")
    os.system("rm {}-altdns-data".format(output_base))
    os.system("sort -u altdnsTemp -o {}-altdns-data".format(output_base))
    os.system("rm altdnsTemp")
    print("\n\n\033[1;31mRunning massDNS for altdns \n\033[1;37m")
    massdnsCMD = "cat {} | {} -r {}/bin/massdns/lists/resolvers.txt -t A -s 8000 -o S -w {}_massdns_altdns.txt".format(
        "{}-altdns-data".format(output_base),
        os.path.join(script_path, "bin/massdns/bin/massdns"),
        script_path,
        output_base,
    )    
    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(massdnsCMD))
    os.system(massdnsCMD)
    os.system("rm {}".format("{}-altdns-data".format(output_base)))
    os.system("cat {}_massdns_altdns.txt | grep xxfeedcafejfoiaeowjnbnmcoampqoqp. > {}_altdns_wilds.txt".format(output_base, output_base))
    os.system("cat {}_altdns_wilds.txt {}_wilds.txt > wildTemp".format(output_base, output_base))
    os.system("rm {}_altdns_wilds.txt".format(output_base))
    os.system("mv wildTemp {}_altdns_wilds.txt".format(output_base))
    stripMassdnsFile("{}_massdns_altdns.txt".format(output_base), 
        "{}_massdns_altdns_strip.txt".format(output_base),
        "{}_massdns_altdns_cname_strip.txt".format(output_base),
        "{}_altdns_wilds.txt".format(output_base))
    print("\n\033[1;31mMasscan for altdns Complete\033[1;37m")
    time.sleep(1)

def stripMassdnsFile(massdnsres, output, cnameOutput, wilds):
    global wildList
    with open(massdnsres, "r") as f:
        massdnsResLines = set(f)
    with open(wilds, "r") as f:
        wildLines = f.readlines()
        wildLines.sort(key=lambda x: len(x))
        cleanWildLines = []
        if len(wildLines) > 0:
            cleanWildLines.append(wildLines[0])
        for wildLine in wildLines:
            writeThisLine = True
            for cleanWild in cleanWildLines:
                if cleanWild[33:] in wildLine[33:]:
                    writeThisLine = False
                    break
            if writeThisLine:
                cleanWildLines.append(wildLine)
    with open(wilds, "w+") as f:
        for cleanWild in cleanWildLines:
            f.writelines(cleanWild)

    # pdb.set_trace()

    cnameOut = open(cnameOutput, "a")
    with open(output, "a") as f:
        for line in massdnsResLines:
            hosts = line
            line_data = line
            if " A 127.0.0.1" in hosts:
                continue
            hosts = hosts.split()[0]
            if hosts.endswith("."):
                hosts = hosts[:-1]
            if not hosts.endswith(domain):
                continue
            if hosts.startswith("xxfeedcafejfoiaeowjnbnmcoampqoqp.") and line_data in cleanWildLines:
                hosts = hosts[33:]
                if "CNAME" in line_data:
                    cnameOut.writelines(hosts + "\n")
                f.writelines(hosts + "\n")
                continue
            wild_line_data = line_data.split(".", 1)[1]
            writeThisLine = True
            for cleanWild in cleanWildLines:
                if cleanWild[33:] in wild_line_data:
                    writeThisLine = False
                    break
            if not writeThisLine:
                continue
            if "CNAME" in line_data:
                cnameOut.writelines(hosts + "\n")
            f.writelines(hosts + "\n")
    cnameOut.close()

def check_gopath(cmd, install_repo):
    if os.environ["GOPATH"]:
        execs = os.listdir(os.path.join(os.environ["GOPATH"], "bin"))
    if cmd in execs:
        print(
            "\n\033[1;31mFound '{}' in your $GOPATH/bin folder please add this to your $PATH\033[1;37m".format(
                cmd
            )
        )
    else:
        ans = input(
            "\n\033[1;31m{} does not appear to be installed, would you like to run `go get -u -v {}`? [y/N]\033[1;37m".format(
                cmd, install_repo
            )
        )

        if ans.lower() == "y":
            print("\n\033[1;31mInstalling {}\033[1;37m".format(install_repo))
            os.system("go get -u -v {}".format(install_repo))
            return True


def amass_passive(rerun=0):
    if which("amass"):
        print("\n\n\033[1;31mRunning Amass \n\033[1;37m")
        starttime = datetime.datetime.now()

        amassFileName = "{}_amass.txt".format(output_base)
        amassCmd = "amass enum -passive -d {} -o {}".format(domain, amassFileName)
        print("\n\033[1;31mRunning Command: \033[1;37m{}".format(amassCmd))
        os.system(amassCmd)
        os.system("cat {} >> {}".format(amassFileName, subdomainAllFile))

        endtime = datetime.datetime.now()
        os.system("echo Complete amass_passive for {} seconds >> {}".format((endtime - starttime).seconds, staticsFile))
        d_count = int(subprocess.check_output('wc -l {}'.format(amassFileName), shell=True).split()[0])
        os.system("echo amass_passive find {} subs >> {}".format(d_count, staticsFile))
        print("\n\033[1;31mAmass Complete\033[1;37m")
        time.sleep(1)
    else:
        print("\n\n\033[1;3mAmass is not currently in your $PATH \n\033[1;37m")


def extractFDNS():
    print("\n\n\033[1;31mRunning extractFDNS \n\033[1;37m")
    starttime = datetime.datetime.now()

    fdns_domain_file = "{}/bin/ExtractSubdomainFromFDNS/{}.csv".format(script_path ,domain)
    if os.path.exists(fdns_domain_file):
        exFDNSf = open(fdns_domain_file, "r")
        exFDNSLines = exFDNSf.read().splitlines()
        exFDNSf.close()
        exFDNS_outputFileName = "{}_exfdns.txt".format(output_base)
        with open(exFDNS_outputFileName, "a") as f:
            for line in exFDNSLines:
                line_strs = line.split(',')
                if len(line_strs) > 2:
                    if line_strs[2] == '\"a\"' or line_strs[2] == '\"cname\"':
                        line_subdomain = line_strs[1][1:-1]  
                        f.writelines(line_subdomain + "\n")
        os.system("cat {} >> {}".format(exFDNS_outputFileName, subdomainAllFile))

        endtime = datetime.datetime.now()
        os.system("echo Complete extractFDNS for {} seconds >> {}".format((endtime - starttime).seconds, staticsFile))
        d_count = int(subprocess.check_output('wc -l {}'.format(exFDNS_outputFileName), shell=True).split()[0])
        os.system("echo extractFDNS find {} subs >> {}".format(d_count, staticsFile))
        print("\n\033[1;31mextractFDNS Complete\033[1;37m")
    else:
        print("\nNo csv data for {}!\n".format(domain))

def subfinder(rerun=0):
    if which("subfinder"):
        print("\n\n\033[1;31mRunning Subfinder \n\033[1;37m")
        starttime = datetime.datetime.now()

        subfinderFileName = "{}_subfinder.txt".format(output_base)
        subfinderCmd = "subfinder -d {} -o {}".format(domain, subfinderFileName)
        print("\n\033[1;31mRunning Command: \033[1;37m{}".format(subfinderCmd))
        os.system(subfinderCmd)
        os.system("cat {} >> {}".format(subfinderFileName, subdomainAllFile))

        endtime = datetime.datetime.now()
        os.system("echo Complete subfinder for {} seconds >> {}".format((endtime - starttime).seconds, staticsFile))
        d_count = int(subprocess.check_output('wc -l {}'.format(subfinderFileName), shell=True).split()[0])
        os.system("echo subfinder find {} subs >> {}".format(d_count, staticsFile))
        print("\n\033[1;31msubfinder Complete\033[1;37m")
        time.sleep(1)
    else:
        print("\n\n\033[1;3mSubfinder is not currently in your $PATH \n\033[1;37m")
        if check_gopath("subfinder", "github.com/subfinder/subfinder") and rerun != 1:
            subfinder(rerun=1)

def massdns():
    # global wildList
    print("\n\n\033[1;31mRunning massdns \n\033[1;37m")
    # 似乎结果也包含了NXDOMAIN且有CNAME的类型
    massdnsCMD = "cat {} | {} -r {}/bin/massdns/lists/resolvers.txt -t A -s 8000 -o S -w {}_massdns_noaltdns.txt".format(
        "{}-domain-unique.txt".format(output_base),
        os.path.join(script_path, "bin/massdns/bin/massdns"),
        script_path,
        output_base,
    )
    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(massdnsCMD))
    os.system(massdnsCMD)
    # generateWildList("{}_massdns_noaltdns.txt".format(output_base), wildList)
    os.system("cat {}_massdns_noaltdns.txt | grep xxfeedcafejfoiaeowjnbnmcoampqoqp. > {}_wilds.txt".format(output_base, output_base))
    stripMassdnsFile("{}_massdns_noaltdns.txt".format(output_base), 
        "{}_massdns_noaltdns_strip.txt".format(output_base),
        "{}_massdns_noaltdns_cname_strip.txt".format(output_base),
        "{}_wilds.txt".format(output_base))
    # writeFiles("massdns")    
    os.system("rm " + "{}-domain-unique.txt".format(output_base))
    os.system("rm " + "{}-all.txt".format(output_base))
    print("\n\033[1;31mMasscan Complete\033[1;37m")
    time.sleep(1)

def massdnsBruteLoop():
    print("\n\n\033[1;31mRunning massdnsBruteLoop \n\033[1;37m")
    starttime = datetime.datetime.now()

    word_file = os.path.join(
        script_path, "bin/SecLists/Discovery/DNS/dns-Jhaddix.txt"
    )
    massdnsBruteLoopFileName = "{}_massdnsBruteLoop.txt".format(output_base)
    masstemp = "{}_massdns_temp.txt".format(output_base)
    masstemp1 = "{}_massdns_temp1.txt".format(output_base)
    masstemp2 = "{}_massdns_temp2.txt".format(output_base)
    massdnsBruteLoopCMD = "python bin/massdns/scripts/subbrute.py {} {} | {} -r resolvers.txt -t A -o S -w {}".format(
        word_file,
        domain,
        os.path.join(script_path, "bin/massdns/bin/massdns"),
        masstemp1,
    )
    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(massdnsBruteLoopCMD))
    os.system(massdnsBruteLoopCMD)
    num_line1 = sum(1 for line in open(masstemp1))
    endtime = datetime.datetime.now()
    os.system("echo Complete massdnsBruteLoop_1 for {} seconds with {} results >> {}".format((endtime - starttime).seconds, num_line1, staticsFile))
    starttime = endtime

    # find wildcard

    for i in range(2):
        os.system("cat {} | awk -F '. ' '{{print $1}}' > {}".format(masstemp1, masstemp))
        massdnsBruteLoopCMD = "cat {} | {} -r popular_resolvers.txt -t A -o S -s 3000 -w {}".format(
            masstemp,
            os.path.join(script_path, "bin/massdns/bin/massdns"),
            masstemp2,
        )
        os.system(massdnsBruteLoopCMD)
        num_line2 = sum(1 for line in open(masstemp2))
        endtime = datetime.datetime.now()
        os.system("echo Complete massdnsBruteLoop_2 for {} seconds with {} results >> {}".format((endtime - starttime).seconds, num_line2, staticsFile))
        starttime = endtime
        num_line1 = num_line2
        os.system("mv {} {}".format(masstemp2, masstemp1))

    os.system("cat {} | awk -F '. ' '{{print $1}}' > {}".format(masstemp1, masstemp))
    os.system("sort -u {} -o {}".format(masstemp, massdnsBruteLoopFileName))
    os.system("cat {} >> {}".format(massdnsBruteLoopFileName, subdomainAllFile))
    
    
    d_count = int(subprocess.check_output('wc -l {}'.format(massdnsBruteLoopFileName), shell=True).split()[0])
    os.system("echo massdnsBruteLoop find {} subs >> {}".format(d_count, staticsFile))
    print("\n\033[1;massdnsBruteLoop Complete\033[1;37m")
    time.sleep(1)

def notified(sub, msg):
    notifySub = sub
    notifyMsg = msg
    Config = configparser.ConfigParser()
    Config.read(os.path.join(script_path, "ext/notifycfg.ini"))
    if (Config.get("Pushover", "enable")) == "True":
        poToken = Config.get("Pushover", "token")
        poUser = Config.get("Pushover", "user")
        if "device" in Config.options("Pushover"):
            poDevice = Config.get("Pushover", "device")
            poRequestPayload = {
                "token": poToken,
                "user": poUser,
                "device": poDevice,
                "title": notifySub,
                "message": notifyMsg,
            }
        else:
            poRequestPayload = {
                "token": poToken,
                "user": poUser,
                "title": notifySub,
                "message": notifyMsg,
            }
            poValidatePayload = {"token": poToken, "user": poUser}
            poValidate = requests.post(
                "https://api.pushover.net/1/users/validate.json",
                data=(poValidatePayload),
            )
            poJsonV = poValidate.json()
            if poJsonV["status"] == 1:
                print("\nPushover Account Validated\n")
                poRequest = requests.post(
                    "https://api.pushover.net/1/messages.json", data=(poRequestPayload)
                )
                poJsonR = poRequest.json()
                if poJsonV["status"] == 1:
                    print("\nPushover Account Notified\n")
                else:
                    print("\nError - Pushover Account Not Notified\n")
            else:
                print("\nError - Pushover Account Not Validated\n")
    if (Config.get("Email", "enable")) == "True":
        gmailUser = Config.get("Email", "user")
        gmailPass = Config.get("Email", "password")
        try:
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(gmailUser, gmailPass)
            subject = "domained Script Complete"
            text = "domained Script Complete for " + domain
            msg = "Subject: {}\n\n{}".format(subject, text)
            server.sendmail(gmailUser, gmailUser, msg)
            server.quit()
            print("\nEmail Notification Sent\n")
        except:
            print("\nError - Email Notification Not Sent\n")

def checkMainDomainWildCard(checkdomain):
    # print("\nChecking wildcard\n")
    rand_domain = "xxfeedcafejfoiaeowjnbnmcoampqoqp.{}".format(checkdomain)
    os.system("dig {} @8.8.8.8 > c_tempCheck".format(rand_domain))
    os.system("dig {} @8.8.8.8 > tempCheck".format(checkdomain))
    dig_c_noerror = len(subprocess.getoutput("cat c_tempCheck | grep NOERROR"))
    dig_c_cname = len(subprocess.getoutput("cat c_tempCheck | grep CNAME"))
    dig_noerror = len(subprocess.getoutput("cat tempCheck | grep NOERROR"))
    dig_cname = len(subprocess.getoutput("cat tempCheck | grep CNAME"))
    os.system("rm tempCheck c_tempCheck")
    if dig_c_noerror > 0:
        if dig_c_cname > 0:
            return CNAMEWILD    # sib CNAME
        elif dig_cname > 0:    
            return NOWILD       # sib A, domain CNAME
        else:
            return AWILD        # sib A, domain A
    else:
        return NOWILD

def options():
    if fresh:
        refreshResolvers(domain)
        return
    if install or upgrade:
        upgradeFiles()
        return
    else:
        if domain:
            # clean old results
            os.system("rm -dfr output/{}".format(domain))
            os.system("mkdir output/{}".format(domain))
            notified("domained Script Started", "domained Script Started for {}".format(domain))
            # subfinder()
            # amass_passive()
            # extractFDNS()
            if mainWildcard == NOWILD:
                massdnsBruteLoop()
            # os.system("sort -u {} -o sorted_temp.txt".format(subdomainAllFile))
            # os.system("mv sorted_temp.txt {}".format(subdomainAllFile))


            # generateUrl()
            # subdomainUrlUniqueFile = "{}-all4one-url-unique.txt".format(output_base)
            # eyewitness(subdomainUrlUniqueFile)
            notified("domained Script Finished", "domained Script Finished for {}".format(domain))
        else:
            print("\nPlease provide a domain. Ex. -d example.com")
    print("\n\033[1;34mAll your subdomain are belong to us\033[1;37m")


if __name__ == "__main__":
    # global wildList
    args = get_args()
    domain = args.domain
    script_path = os.path.dirname(os.path.realpath(__file__))
    output_base = "{}/output/{}/{}".format(script_path, domain, domain)
    subdomainAllFile = "{}-all.txt".format(output_base)
    staticsFile = "{}-reconstatics.txt".format(output_base)
    secure = args.secure
    bruteforce = args.bruteforce
    upgrade = args.upgrade
    install = args.install
    ports = args.ports
    vpn = args.vpn
    quick = args.quick
    bruteall = args.bruteall
    fresh = args.fresh
    notify = args.notify
    active = args.active
    useEyewitness = args.eyewitness
    mainWildcard = checkMainDomainWildCard(domain)
    options()