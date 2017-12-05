# Defenses against ARP Cache Poisoning Attacks.
The code on this project was developed to evaluate some the available defenses against ARP Cache Poisoning attacks. You can find the paper [here](). We implement the algorithms described in the following research papers:
* [1] N. Tripathi, B.M. Mehtre. An ICMP based secondary cache approach for the detection and 
     prevention of ARP poisoning. 4th IEEE ICCIC, 2013.
* [2] P. Pandey. Prevention of ARP spoofing: A probe packet based technique. IEEE IACC, 2013.

## Installation instructions
For this project, one needs to have scapy installed. We recommend installing it on a virtual environment using pip. These instructions are for Mac OS X users.

To install virtualenv and pip:
```
$ sudo easy_install pip
$ pip install --upgrade virtualenv
$ virtualenv --system-site-package directory
```
This directory can be anywhere where you would like to install your environment. For example: ~/Documents/arp_defenses_env

To run virtualenv:
```
$ source ~/Documents/arp_defenses_env/bin/activate
```
You should replace the path with the chosen path for your environment installation.

To install scapy:
Inside of your virtual environment, run the following command:
```
$ pip install scapy
```

Install Scapy's dependencies to avoid import errors (https://stackoverflow.com/questions/40272077/importerror-no-module-named-dumbnet-when-trying-to-run-a-script-that-leverage)
```
cd
git clone https://github.com/dugsong/libdnet.git
cd libdnet
./configure && make
cd python
python setup.py install
```

Test your setup:
```
$ source ~/Documents/arp_defenses/bin/activate
$ sudo scapy
```
Or
```
$ python
>>> from scapy.all import *
```

To exit the virtual environment:
```
$ deactivate
```

## Getting the code
To get the code for these solutions, create a folder where you would like to store the code, and execute the following command:
```
git clone https://github.com/rva5120/arp_def_tools
```

## Running the defenses
These solutions assume that the user's ethernet interface is 'en0'. If this is not the case, please change the variable eth_interface accordingly.

### Running ICMP Secondary Cache [1]
This implementation requires the user to manually enter the current ARP Table at the time of starting the program. Please go to the file "icmp_sec_cache.py", and populate the icmp_cache mapping structure. Feel free to add more mappings aside from the default provided on the script.

To run the code, execute the following command and enter your admin password:
```
sudo python icmp_sec_cache.py
```

### Running E-SDE Solution [2]
To run the code, execute the following command and enter your admin password:
```
sudo python e_sde.py
```

The programs will alert you if an attack is happening.
