import ipaddress
import boto3 
import sys

REGION = 'us-west-2'
ec2_client = boto3.client('ec2', region_name=REGION.strip())


def usage():
    print('It accepts 2 arguments.\n \t cidr-type-->IPV4 or IPV6 \n \t cidr address')
    print('Usage: '+sys.argv[0]+' cidr-type ' + 'cidr')


def find_available_ips(cidr, cidrtype):
    USED_IPS = []
    response = ec2_client.describe_network_interfaces()
    for ni in response['NetworkInterfaces']:
        for ip in ni['PrivateIpAddresses']:
            USED_IPS.append(ip['PrivateIpAddress'])

    if cidrtype == "IPV4":     
        for ip in ipaddress.IPv4Network(cidr):
            if str(ip) not in USED_IPS:
                print(ip)
    if cidrtype == "IPV6":  
        for ip in ipaddress.IPv6Network(cidr):
            if str(ip) not in USED_IPS:
                print(ip)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()
    else:
        cidr = sys.argv[2]
        cidrtype = sys.argv[1]
        find_available_ips(cidr,cidrtype)