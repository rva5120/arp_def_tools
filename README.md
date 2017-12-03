# Defenses against ARP Cache Poisoning Attacks.
In this project, we implement the algorithms described in the following research papers:
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

Test your setup:
```
$ source ~/Documents/arp_defenses/bin/activate
$ sudo scapy
```
This should start up scapy on your terminal.

To exit the virtual environment:
```
$ deactivate
```

## Getting the code
To get the code for these solutions, create a folder where you would like to store the code, and execute the following command:
```
git clone https://github.com/rva5120/arp_def_tools
```

## Running ICMP Secondary Cache [1]


## Running E-SDE Solution [2]
The E-SDE solution assumes that the user's ethernet interface is 'en0'. If this is not the case, please change the variable eth_interface accordingly.

To run the code, execute the following command and enter your admin password:
```
sudo python e_sde.py
```

The program will alert you if an attack is happening.
