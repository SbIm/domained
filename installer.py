import os
import time
import subprocess


SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))

def refreshResolvers(target):
    os.chdir(SCRIPT_PATH)
    os.system("rm -dfr ./bin/bass")
    os.system("git clone https://github.com/SbIm/bass.git ./bin/bass")
    # os.system("wget https://public-dns.info/nameserver/us.txt")
    # os.system("wget https://public-dns.info/nameserver/gb.txt")
    # os.system("wget https://public-dns.info/nameserver/de.txt")
    # os.system("wget https://public-dns.info/nameserver/jp.txt")
    # os.system("cat us.txt >> ./bin/bass/resolvers/public.txt")
    # os.system("cat gb.txt >> ./bin/bass/resolvers/public.txt")
    # os.system("cat de.txt >> ./bin/bass/resolvers/public.txt")
    # os.system("cat jp.txt >> ./bin/bass/resolvers/public.txt")
    # os.system("sort -u ./bin/bass/resolvers/public.txt -o ./bin/bass/resolvers/public.txt")
    # os.system("dnsvalidator -tL ./bin/bass/resolvers/public.txt -threads 20 -o temp_resolvers.txt")
    os.system("dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 30 -o temp_resolvers.txt")
    os.system("cat temp_resolvers.txt >> ./bin/bass/resolvers/public.txt")
    os.system("sort -u ./bin/bass/resolvers/public.txt -o ./bin/bass/resolvers/public.txt")
    os.system("rm temp_resolvers.txt")
    os.system("python3 bin/bass/bass.py -d {} -o temp_resolvers.txt".format(target))
    # os.system("python3 health_resolvers.py {}".format(target))
    # os.system("mv temp_health_resolvers.txt resolvers.txt")
    os.system("mv temp_resolvers.txt resolvers.txt")

def upgradeFiles():
    """Upgrade all the required files
    """
    binpath = os.path.join(SCRIPT_PATH, "bin")
    old_wd = os.getcwd()
    if not os.path.exists(binpath):
        os.makedirs(binpath)
    else:
        print("Removing old bin directory: {}".format(binpath))
        os.system("rm -rf {}".format(binpath))
        os.makedirs(binpath)
    print("Changing into domained home: {}".format(SCRIPT_PATH))
    os.chdir(SCRIPT_PATH)
    unameChk = subprocess.check_output(["uname", "-am"]).decode("utf-8")

    eyeWitnessUpgrade = "git clone https://github.com/FortyNorthSecurity/EyeWitness.git ./bin/EyeWitness"
    os.system(eyeWitnessUpgrade)
    eyeInstallReq = "bash bin/EyeWitness/setup/setup.sh"
    os.system(eyeInstallReq)
    cpphantomjs = "cp phantomjs ./bin/EyeWitness/bin/"
    os.system(cpphantomjs)
    movephantomjs = "mv phantomjs bin/"
    os.system(movephantomjs)

    amassUpgrade = "go get -u -v github.com/OWASP/Amass/v3/..."
    os.system("export GO111MODULE=on")
    os.system(amassUpgrade)
    subfinderUpgrade = "go get -u -v github.com/subfinder/subfinder"
    os.system(subfinderUpgrade)
    massdnsUpgrade = "git clone --branch master --single-branch https://github.com/blechschmidt/massdns ./bin/massdns"
    os.system(massdnsUpgrade)
    massdnsMake = "make -C ./bin/massdns"
    os.system(massdnsMake)
    os.system("go get -u -v github.com/jakejarvis/subtake")
    os.system("pip3 install dnsgen")
    os.system("GO111MODULE=on go get -u -v github.com/projectdiscovery/shuffledns/cmd/shuffledns")
    os.system("git clone https://github.com/SbIm/ExtractSubdomainFromFDNS.git ./bin/ExtractSubdomainFromFDNS")
    os.system("git clone https://github.com/vortexau/dnsvalidator.git ./bin/dnsvalidator")
    dnsvalidatorpath = os.path.join(binpath, "dnsvalidator")
    os.chdir(dnsvalidatorpath)
    os.system("python3 setup.py install")
    os.chdir(SCRIPT_PATH)    
    os.system("git clone https://github.com/Abss0x7tbh/bass.git ./bin/bass")

    # wordlists
    # bin/commonspeak2-wordlists/subdomains/subdomains.txt, 48k
    os.system("git clone https://github.com/assetnote/commonspeak2-wordlists.git ./bin/commonspeak2-wordlists")
    # bin/SecLists/Discovery/DNS/dns-Jhaddix.txt, 2170k
    # bin/SecLists/Discovery/DNS/subdomains-top1million-110000.txt, 110k
    # bin/SecLists/Discovery/DNS/subdomains-top1million-20000.txt, 20k
    # bin/SecLists/Discovery/DNS/subdomains-top1million-5000.txt, 5k
    os.system("git clone https://github.com/danielmiessler/SecLists.git ./bin/SecLists")

    print("\n\033[1;31mAll tools installed \033[1;37m")
    print("Changing back to old working directory: {}".format(old_wd))
    os.chdir(old_wd)
