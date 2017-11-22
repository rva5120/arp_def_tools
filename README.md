# Defenses against ARP Cache Poisoning Attacks.
In this project, we implement the algorithms described in the following research papers:
* [1]
* [2]
* [3]

## Installation instructions
For this project, one needs to have scapy installed. We recommend installing it on a virtual environment using pip. These instructions are for Mac OS X users.

To install virtualenv and pip:
`$ sudo easy_install pip`
`$ pip install --upgrade virtualenv`
`$ virtualenv --system-site-package directory`
This directory can be anywhere where you would like to install your environment. For example: ~/Documents/arp_defenses_env

To run virtualenv:
`$ source ~/Documents/arp_defenses_env/bin/activate`
You should replace the path with the chosen path for your environment installation.

To install scapy:
Inside of your virtual environment, run the following command:
`$ pip install scapy`

Test your setup:
`$ source ~/Documents/arp_defenses/bin/activate`
`$ sudo scapy`
This should start up scapy on your terminal.

To exit the virtual environment:
`$ deactivate`
