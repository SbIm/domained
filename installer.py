import os
import time
import subprocess


SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))


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

    # wordlists
    sublstUpgrade = "git clone https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056 ./bin/sublst"
    os.system(sublstUpgrade)
    SLsublstUpgrade = "wget -O ./bin/sublst/sl-domains.txt https://raw.githubusercontent.com/\
danielmiessler/SecLists/master/Discovery/DNS/sortedcombined-knock-dnsrecon-fierce-reconng.txt"
    os.system(SLsublstUpgrade)

    amassUpgrade = "go get -u -v github.com/OWASP/Amass/..."
    os.system(amassUpgrade)
    subfinderUpgrade = "go get -u -v github.com/subfinder/subfinder"
    os.system(subfinderUpgrade)
    massdnsUpgrade = "git clone --branch master --single-branch https://github.com/blechschmidt/massdns ./bin/massdns"
    os.system(massdnsUpgrade)
    massdnsMake = "make -C ./bin/massdns"
    os.system(massdnsMake)

    # os.system("cp ./bin/massdns/lists/resolvers.txt ./")
    os.system("pip3 install dnsgen")
    os.system("git clone https://github.com/assetnote/commonspeak2-wordlists.git ./bin/commonspeak2-wordlists")
    os.system("git clone https://github.com/SbIm/ExtractSubdomainFromFDNS.git ./bin/ExtractSubdomainFromFDNS")
    os.system("go get -u -v github.com/jakejarvis/subtake")

    print("\n\033[1;31mAll tools installed \033[1;37m")
    print("Changing back to old working directory: {}".format(old_wd))
    os.chdir(old_wd)
