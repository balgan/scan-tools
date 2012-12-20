import iptools
from netaddr import IPNetwork
FILE = open('GB.CIDRS','r')
FILE2 = open('list.txt','a')
ips = []
i = 0
for line in FILE:
	for ip in IPNetwork(line):

		FILE2.write(str(ip)+"\n")
