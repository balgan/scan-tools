import commands
import redis
import sys
import subprocess

IPS = "./list.txt"
port = sys.argv[1]

def main():


        r = redis.StrictRedis(host='localhost', port=6379, db=0)
        comm1 = subprocess.Popen('cat ./list.txt',stdout=subprocess.PIPE,shell=True)
        print "DONE HERE"
        comm2 = subprocess.Popen(['./udpblast ' +port+' ../packets/'+port+'.pkt 20000'],stdin$
        comm1.stdout.close()
        print comm2.communicate()[0]
main()