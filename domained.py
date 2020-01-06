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
        "--fresh", help="Remove output Folder", action="store_true", default=False
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


def banner():
    print(
        """\033[1;31m
         ___/ /__  __ _  ___ _(_)__  ___ ___/ /
        / _  / _ \/  ' \/ _ `/ / _ \/ -_) _  /
        \_,_/\___/_/_/_/\_,_/_/_//_/\__/\_,_/
    \033[1;34m\t\t\tgithub.com/cakinney\033[1;m"""
    )

def sublist3r(brute=False):
    print("\n\n\033[1;31mRunning Sublist3r \n\033[1;37m")
    sublist3rFileName = "{}_sublist3r.txt".format(output_base)
    Subcmd = "python {} -v -t 15 {} -d {} -o {}".format(
        os.path.join(script_path, "bin/Sublist3r/sublist3r.py"),
        "-b" if brute else "",
        domain,
        sublist3rFileName,
    )
    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(Subcmd))
    os.system(Subcmd)
    writeFiles("sublist3r")
    print("\n\033[1;31mSublist3r Complete\033[1;37m")
    time.sleep(1)
    #if brute:
    #    eyewitness(sublist3rFileName)


def enumall():
    print("\n\n\033[1;31mRunning Enumall \n\033[1;37m")
    enumallCMD = "python {} {}".format(
        os.path.join(script_path, "bin/domain/enumall.py"), domain
    )
    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(enumallCMD))
    os.system(enumallCMD)
    print("\n\033[1;31menumall Complete\033[1;37m")
    rmcsvCMD = "rm {}/{}.csv".format(
        script_path, domain
    )
    movlstCMD = "mv {}/{}.lst {}_enumall.lst".format(
        script_path, domain, output_base
    )
    os.system(rmcsvCMD)
    os.system(movlstCMD)
    writeFiles("enumall")    
    time.sleep(1)

def subbrute():
    print("\n\n\033[1;31mRunning subbrute \n\033[1;37m")
    word_file = os.path.join(
        # script_path, "bin/sublst/all.txt" if bruteall else "bin/sublst/sl-domains.txt"
        script_path, "bin/sublst/all.txt"
    )
    # subbruteCMD = "python bin/subbrute/subbrute.py -s {} -c 15 -o {}_subbrute.txt {}".format(
    #     word_file, 
    #     output_base,
    #     domain,
    # )
    subbruteCMD = "python bin/massdns/scripts/subbrute.py {} {} > {}_subbrute.txt".format(
        word_file, 
        domain,
        output_base,
    )
    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(subbruteCMD))
    os.system(subbruteCMD)
    writeFiles("subbrute")
    print("\n\033[1;31mSubbrute Complete\033[1;37m")
    time.sleep(1)

def massdns():
    # global wildList
    print("\n\n\033[1;31mRunning massdns \n\033[1;37m")
    # 似乎结果也包含了NXDOMAIN且有CNAME的类型
    massdnsCMD = "cat {} | {} -r {}/bin/massdns/lists/resolvers.txt -t A --resolve-count 500 -o S -w {}_massdns_noaltdns.txt".format(
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

def altdns():
    # global altdnsWildList
    print("\n\n\033[1;31mRunning altdns \n\033[1;37m")
    word_file = os.path.join(
        # script_path, "bin/sublst/all.txt" if bruteall else "bin/sublst/sl-domains.txt"
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
    massdnsCMD = "cat {} | {} -r {}/bin/massdns/lists/resolvers.txt -t A --resolve-count 500 -o S -w {}_massdns_altdns.txt".format(
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
        cleanWildLines = [wildLines[0]]
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


def amass(rerun=0):
    if which("amass"):
        print("\n\n\033[1;31mRunning Amass \n\033[1;37m")
        amassFileName = "{}_amass.txt".format(output_base)
        amassCmd = "amass enum -passive -d {} -o {}".format(domain, amassFileName)
        print("\n\033[1;31mRunning Command: \033[1;37m{}".format(amassCmd))
        os.system(amassCmd)
        print("\n\033[1;31mAmass Complete\033[1;37m")
        writeFiles("amass")
        time.sleep(1)
    else:
        print("\n\n\033[1;3mAmass is not currently in your $PATH \n\033[1;37m")
        if check_gopath("amass", "github.com/OWASP/Amass/...") and rerun != 1:
            amass(rerun=1)

def extractFDNS():
    print("\n\n\033[1;31mRunning extractFDNS \n\033[1;37m")
    fdns_domain_file = "{}/bin/ExtractSubdomainFromFDNS/{}.csv".format(script_path ,domain)
    if os.path.exists(fdns_domain_file):
        exFDNSf = open(fdns_domain_file, "r")
        exFDNSLines = exFDNSf.read().splitlines()
        exFDNSf.close()

        with open("{}_exfdns.txt".format(output_base), "a") as f:
            for line in exFDNSLines:
                line_strs = line.split(',')
                if len(line_strs) > 2:
                    if line_strs[2] == '\"a\"' or line_strs[2] == '\"cname\"':
                        line_subdomain = line_strs[1][1:-1]  
                        f.writelines(line_subdomain + "\n")
        writeFiles("exfdns")
        print("\n\033[1;31mextractFDNS Complete\033[1;37m")
    else:
        print("\nNo csv data for {}!\n".format(domain))

def subfinder(rerun=0):
    if which("subfinder"):
        print("\n\n\033[1;31mRunning Subfinder \n\033[1;37m")
        subfinderFileName = "{}_subfinder.txt".format(output_base)
        subfinderCmd = "subfinder -d {} -o {}".format(domain, subfinderFileName)
        print("\n\033[1;31mRunning Command: \033[1;37m{}".format(subfinderCmd))
        os.system(subfinderCmd)
        print("\n\033[1;31msubfinder Complete\033[1;37m")
        writeFiles("subfinder")
        time.sleep(1)
    else:
        print("\n\n\033[1;3mSubfinder is not currently in your $PATH \n\033[1;37m")
        if check_gopath("subfinder", "github.com/subfinder/subfinder") and rerun != 1:
            subfinder(rerun=1)


def eyewitness(filename):
    print("\n\n\033[1;31mRunning EyeWitness  \n\033[1;37m")
    # EWHTTPScriptIPS = "meg -d 10 -c 200 -s 200 / {} {}_meg".format(
    #     filename,
    #     output_base,
    # )
    os.system("rm {}/geckodriver.log".format(script_path))
    EWHTTPScriptIPS = "{}/bin/EyeWitness/EyeWitness.py -f {} --no-prompt --web -d {}_Eyewitness".format(script_path, 
        filename,
        output_base,
    )
    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(EWHTTPScriptIPS))
    os.system(EWHTTPScriptIPS)
    print("\a")


def writeFiles(name):
    """Writes info of all hosts from subhosts
    """
    subdomainCounter = 0
    subdomainAllFile = "{}-all.txt".format(output_base)
    subdomainUniqueFile = "{}-domain-unique.txt".format(output_base)
    uniqueDomainsOut = open(subdomainUniqueFile, "a+")
    fileExt = {
        "sublist3r": ".txt",
        "enumall": ".lst",
        "massdns": ".txt",
        "amass": ".txt",
        "subbrute": ".txt",
        "subfinder": ".txt",
        "exfdns": ".txt",
    }
    fileName = output_base + "_" + name + fileExt[name]

    print("\n Opening %s File" % name)
    print("\n path is %s " % fileName)
    try:
        with open(fileName, "r") as f:
            SubHosts = f.read().splitlines()

        with open(subdomainAllFile, "a") as f:
            f.writelines("\n\n" + name)
            for hosts in SubHosts:
                hosts = "".join(hosts)
                if name == "subfinder" and hosts.startswith('.'):
                    hosts = hosts[1:]
                f.writelines("\n" + hosts)
                uniqueDomainsOut.writelines(hosts + "\n")
                hostsArr = hosts.split(".", 1)
                wildCardhosts = "xxfeedcafejfoiaeowjnbnmcoampqoqp." + hostsArr[1]
                uniqueDomainsOut.writelines(wildCardhosts + "\n")
                subdomainCounter = subdomainCounter + 1
        os.remove(fileName)
        uniqueDomainsOut.close()
        os.system("sort -u {} -o sorted_temp.txt".format(subdomainUniqueFile))
        os.system("mv sorted_temp.txt {}".format(subdomainUniqueFile))
        print("\n{} Subdomains discovered by {}".format(subdomainCounter, name))
    except:
        print("\nError Opening %s File!\n" % name)
    return subdomainCounter

def generateUrl():
    print("\nGenerating Urls Lists\n")
    altdnsSubdomainFile = "{}_massdns_altdns_strip.txt".format(output_base)
    altdnsCnameSubdomainFile = "{}_massdns_altdns_cname_strip.txt".format(output_base)
    noaltdnsSubdomainFile = "{}_massdns_noaltdns_strip.txt".format(output_base)
    noaltdnsCnameSubdomainFile = "{}_massdns_noaltdns_cname_strip.txt".format(output_base)
    all4oneFile = "{}_massdns_all4one.txt".format(output_base)
    all4oneCnameFile = "{}_massdns_all4one_cname.txt".format(output_base)
    if mainWildcard == NOWILD:
        os.system("cat {} {} > temp.txt".format(altdnsSubdomainFile, noaltdnsSubdomainFile))
        os.system("cat {} {} > cnametemp.txt".format(altdnsCnameSubdomainFile, noaltdnsCnameSubdomainFile))
        os.system("rm {} {} {} {}".format(altdnsSubdomainFile, noaltdnsSubdomainFile, 
                                        altdnsCnameSubdomainFile, noaltdnsCnameSubdomainFile))
    else:
        os.system("cat {} > temp.txt".format(noaltdnsSubdomainFile))
        os.system("cat {} > cnametemp.txt".format(noaltdnsCnameSubdomainFile))
        os.system("rm {} {}".format(noaltdnsSubdomainFile, noaltdnsCnameSubdomainFile))
    os.system("sort -u temp.txt -o {}".format(all4oneFile))
    os.system("sort -u cnametemp.txt -o {}".format(all4oneCnameFile))
    os.system("rm temp.txt")
    os.system("rm cnametemp.txt")
    with open(all4oneFile, "r") as f:
        uniqueDomains = f.read().splitlines()
        subdomainUrlUniqueFile = "{}-all4one-url-unique.txt".format(output_base)
        uniqueDomainsUrlOut = open(subdomainUrlUniqueFile, "w")
        for domains in uniqueDomains:
            domains = domains.replace("\n", "")
            if domains.endswith(domain):
                uniqueDomainsUrlOut.writelines("https://{}\n".format(domains))
                if ports is not False:
                    uniqueDomainsUrlOut.writelines("https://{}:8443\n".format(domains))
                if secure is False:
                    uniqueDomainsUrlOut.writelines("http://{}\n".format(domains))
                    if ports is not False:
                        uniqueDomainsUrlOut.writelines("http://{}:8080\n".format(domains))
        uniqueDomainsUrlOut.close()

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


def options():
    if fresh:
        os.system("rm -r output")
        newpath = r"output"
        os.makedirs(newpath)
    if install or upgrade:
        upgradeFiles()
    else:
        if domain:
            # clean old results
            os.system("rm -dfr output/{}".format(domain))
            os.system("mkdir output/{}".format(domain))
            # notify domained begins
            if notify:
                notified("domained Script Started", "domained Script Started for {}".format(domain))
            enumall()
            subfinder()
            amass()
            extractFDNS()
            if mainWildcard == NOWILD:
                subbrute()
            massdns()
            if mainWildcard == NOWILD:
                altdns()
            generateUrl()
            if useEyewitness:
                subdomainUrlUniqueFile = "{}-all4one-url-unique.txt".format(output_base)
                eyewitness(subdomainUrlUniqueFile)
            if notify:
                notified("domained Script Finished", "domained Script Finished for {}".format(domain))
        else:
            print("\nPlease provide a domain. Ex. -d example.com")
    print("\n\033[1;34mAll your subdomain are belong to us\033[1;37m")


if __name__ == "__main__":
    # global wildList
    banner()
    args = get_args()
    domain = args.domain
    script_path = os.path.dirname(os.path.realpath(__file__))
    output_base = "{}/output/{}/{}".format(script_path, domain, domain)
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