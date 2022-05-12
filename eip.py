#!/usr/bin/env python
"""
This python script will add floating ip to the worker nodes.
Accepts no args
"""
from pickle import NONE
import boto3
import time
import logging
import subprocess
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
import json
import os
import sys
from botocore.exceptions import ClientError
import ipaddress

FLOATING_IP=os.getenv('FLOATING_IP')
FLOATING_EIP = None
FLOATING_SG=[]
start_time = time.time()

FORCE = False
if len(sys.argv) == 2:
    FORCE = sys.argv[1]

def shell_run_cmd(cmd,retCode=0):
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,encoding="utf-8")
    stdout, stderr = p.communicate()
    exit_code = p.wait()
    print(stdout)
    return stdout, exit_code
def get_floatingip_type(FLOATING_IP):
    IP_TYPE = NONE
    try:
        if "eipalloc" in FLOATING_IP:
            IP_TYPE = "EIP"
        else:
            ip = ipaddress.ip_address(FLOATING_IP)
            if isinstance(ip, ipaddress.IPv4Address):
                print("{} Floating IP is IPv4 ".format(FLOATING_IP))
                IP_TYPE = "IPV4"
            elif isinstance(ip, ipaddress.IPv6Address):
                print("{} Floating IP is IPv6".format(FLOATING_IP))
                IP_TYPE = "IPV6"
    except ValueError:
        print("{} Floating IP is Invalid".format(FLOATING_IP))
    return IP_TYPE
# cmd='curl http://169.254.169.254/latest/meta-data/local-hostname'
NODE_DNS=os.getenv('MY_HOSTNAME')
cmd_region = "echo $MY_HOSTNAME | awk -F '.' {'print $2'}"
REGION, exit_code = shell_run_cmd(cmd_region)
REG = REGION.strip()
if REG == 'ec2':
    REGION = 'us-east-1'
ec2_client = boto3.client('ec2', region_name=REGION.strip())
# NODE_DNS, exit_code = shell_run_cmd(cmd)

def get_interface_attr(NODE_DNS):
    instance_attr = {}
    try: 
        response = ec2_client.describe_network_interfaces(
        Filters=[
            {
                'Name': 'private-dns-name',
                'Values': [
                    NODE_DNS,
                ]
            }
        ]
        )
        FLOATING_SUBNET=response['NetworkInterfaces'][0]['SubnetId']
        for sg in response['NetworkInterfaces'][0]['Groups']:
            FLOATING_SG.append(sg['GroupId'])
        INSTANCE_IP=response['NetworkInterfaces'][0]['PrivateIpAddress']
        INSTANCE_ID=response['NetworkInterfaces'][0]['Attachment']['InstanceId']
        instance_attr['FLOATING_SUBNET'] = FLOATING_SUBNET
        instance_attr['FLOATING_SG'] = FLOATING_SG
        instance_attr['INSTANCE_IP'] = INSTANCE_IP
        instance_attr['INSTANCE_ID'] = INSTANCE_ID
    except ClientError as err:
        print("Unexpected error in retrievig ENI information %s" % err)
    get_interface_attr_time = time.time()
    print("get_interface_attr time elapsed", get_interface_attr_time - start_time)
    return instance_attr

def create_network_interface(result):
    eni_id = None
    FLOATING_SG=result['FLOATING_SG']
    FLOATING_SUBNET=result['FLOATING_SUBNET']
    try: 
        response = ec2_client.describe_network_interfaces(
            Filters=[
                {
                    'Name': 'tag:Name',
                    'Values': [
                        'FloationgIP',
                    ]
                }
            ]
        )   
        if not response['NetworkInterfaces']:
            print("Interface does not exists..creating")
            IP_TYPE = get_floatingip_type(FLOATING_IP)
            if IP_TYPE == "IPV4":     
                response_create_ni = ec2_client.create_network_interface(
                    Description='FloatingIpInterface',
                    Groups=FLOATING_SG,
                    PrivateIpAddress=FLOATING_IP,
                    SubnetId=FLOATING_SUBNET,
                    TagSpecifications=[
                        {
                            "ResourceType": "network-interface",
                            "Tags": [{"Key": "node.k8s.amazonaws.com/no_manage", "Value": "true"},{"Key": "Name", "Value": "FloationgIP"}],
                        }
                    ],
                )
                eni_id = response_create_ni['NetworkInterface']['NetworkInterfaceId']
            elif IP_TYPE == "IPV6":     
                response_create_ni = ec2_client.create_network_interface(
                    Description='FloatingIpInterface',
                    Groups=FLOATING_SG,
                    Ipv6Addresses=[
                    {
                    'Ipv6Address': FLOATING_IP
                    },
                    ],
                    SubnetId=FLOATING_SUBNET,
                    TagSpecifications=[
                        {
                            "ResourceType": "network-interface",
                            "Tags": [{"Key": "node.k8s.amazonaws.com/no_manage", "Value": "true"},{"Key": "Name", "Value": "FloationgIP"}],
                        }
                    ],
                )
                eni_id = response_create_ni['NetworkInterface']['NetworkInterfaceId']
            elif IP_TYPE == 'EIP':
                response_create_ni = ec2_client.create_network_interface(
                    Description='FloatingIpInterface',
                    Groups=FLOATING_SG,
                    SubnetId=FLOATING_SUBNET,
                    TagSpecifications=[
                        {
                            "ResourceType": "network-interface",
                            "Tags": [{"Key": "node.k8s.amazonaws.com/no_manage", "Value": "true"},{"Key": "Name", "Value": "FloationgIP"}],
                        }
                    ],
                )
                eni_id = response_create_ni['NetworkInterface']['NetworkInterfaceId']
                FLOATING_EIP = response_create_ni['NetworkInterface']['PrivateIpAddress']
                print("Assosciateing EIP to floating ip interface")
                ec2_client.associate_address(AllocationId=FLOATING_IP, AllowReassociation=True, NetworkInterfaceId = eni_id)
        else:
            eni_id = response['NetworkInterfaces'][0]['NetworkInterfaceId']
        create_network_interface_time = time.time()
        print("create_network_interface_time elapsed", create_network_interface_time - start_time)
    except ClientError as err:
        print("Unexpected error in creating network interface %s" % err)  
    return eni_id

def deattach_ni_ec2_if_atatched(instanceid, eni,FORCE):
    try:
        response_eni = ec2_client.describe_network_interfaces(
            NetworkInterfaceIds=[
                eni,
            ]
        )
        ENI_ATTACH_STATUS=response_eni['NetworkInterfaces'][0]['Status']  
        if ENI_ATTACH_STATUS == 'in-use':
            INSTANCE_ID = response_eni['NetworkInterfaces'][0]['Attachment']['InstanceId']
            INSTANCE_STATUS = 'FAILED'
            res=ec2_client.describe_instance_status(InstanceIds=[(INSTANCE_ID)])
            if res['InstanceStatuses']:
                if res['InstanceStatuses'][0]['InstanceStatus']['Status'] == 'ok' and res['InstanceStatuses'][0]['SystemStatus']['Status'] == 'ok' and res['InstanceStatuses'][0]['InstanceState']['Name'] == 'running':
                    INSTANCE_STATUS = 'OK'
            else:
                time.sleep(5)
            if INSTANCE_STATUS == 'OK':
                print("Same healthy instance is attached.")
                deattach_ni_ec2_if_atatched_time = time.time()
                print("deattach_ni_ok_ec2_if_atatched_time elapsed", deattach_ni_ec2_if_atatched_time - start_time)
            else:
            # if response_eni['NetworkInterfaces'][0]['Attachment']['InstanceId'] != instance_id:
                print("Dettaching ENI from old failed instance")
                ENI_ATTACH_ID=response_eni['NetworkInterfaces'][0]['Attachment']['AttachmentId']
                if FORCE:
                    res = ec2_client.detach_network_interface(
                        AttachmentId=ENI_ATTACH_ID,
                        Force=True
                    )
                else:
                    res = ec2_client.detach_network_interface(
                        AttachmentId=ENI_ATTACH_ID)                 
                # if res['ResponseMetadata']['HTTPStatusCode'] != 200:
                #     time.sleep(20)
                #     ec2_client.detach_network_interface(
                #     AttachmentId=ENI_ATTACH_ID,
                #     Force=FORCE
                # )
                # else:
                counter = 1
                while counter < 30:
                    response_eni = ec2_client.describe_network_interfaces(
                        NetworkInterfaceIds=[
                        eni,
                        ]
                        )
                    print("counter to detach instance", counter)
                    counter += 1
                    ENI_ATTACH_STATUS=response_eni['NetworkInterfaces'][0]['Status'] 
                    if ENI_ATTACH_STATUS == 'available':
                        print("ENI is {} now".format(ENI_ATTACH_STATUS))
                        deattach_ni_ec2_if_atatched_time = time.time()
                        print("deattach_ni_ec2_if_atatched_time elapsed", deattach_ni_ec2_if_atatched_time - start_time)
                        break
                    else:
                        time.sleep(5)
                attach_ni_ec2(eni, instanceid)
        else:
            deattach_ni_ec2_if_atatched_time = time.time()
            print("deattach_avail_ni_ec2_if_atatched_time elapsed", deattach_ni_ec2_if_atatched_time - start_time)
            attach_ni_ec2(eni, instanceid)
    except ClientError as err:
        print("Unexpected error in dettaching interface from old instance %s" % err) 


def arp_eth_status(index):
    cmd_eth_status = 'cat /sys/class/net/eth{}/operstate'.format(index)
    ethout,ethout_exit_code = shell_run_cmd(cmd_eth_status)
    ethupout = ""
    if ethout_exit_code == 0:
        if ethout == 'up\n':
            print("Fetching eth info")
            cmd = 'ip addr show dev eth{}'.format(index)
            ethupout,ethupout_exit_code = shell_run_cmd(cmd)
        else:
            print("Bringing eth up in if else")
            cmd = 'ec2ifup eth{}'.format(index)
            ethupout,ethupout_exit_code = shell_run_cmd(cmd)
    else:
        print("Bringing eth up in else")
        cmd = 'ec2ifup eth{}'.format(index)
        print("cmd ", cmd)
        ethupout, exit_code = shell_run_cmd(cmd)
    if FLOATING_EIP is None:
        cmd_arp = 'arping -c 4 -A -I eth4 {}'.format(FLOATING_IP)
    else:
        cmd_arp = 'arping -c 4 -A -I eth4 {}'.format(FLOATING_EIP)
    arpout,arpout_exit_code = shell_run_cmd(cmd_arp)
    print('---------------------------------------------------')
    print("Response from bringing up network interface\n{}".format(ethupout))
    print('---------------------------------------------------')
    print("Response from sending the ARP\n{}".format(arpout))
    print('---------------------------------------------------')
    arp_eth_status_time = time.time()
    print("arp_eth_status_time_time elapsed", arp_eth_status_time - start_time)

def attach_ni_ec2(eni, instance_id):
    response = ec2_client.describe_network_interfaces(
        Filters=[
            {
                'Name': 'attachment.instance-id',
                'Values': [
                    instance_id,
                ]
            }
            ]
    )
    index = 0 
    for i in response['NetworkInterfaces']:
       index = index + 1
    try:
        result = ec2_client.attach_network_interface(NetworkInterfaceId = eni, InstanceId = instance_id, DeviceIndex = index)
        print('---------------------------------------------------')
        print("Response from Attaching Interface to EC2\n{}".format(result))
        print('---------------------------------------------------')
        counter = 1
        while counter < 30:
            response_eni = ec2_client.describe_network_interfaces(
                NetworkInterfaceIds=[
                eni,
                ]
                )
            counter += 1
            print("counter to Attach instance", counter)
            ENI_ATTACH_STATUS=response_eni['NetworkInterfaces'][0]['Status'] 
            if ENI_ATTACH_STATUS == 'in-use':
                break
            else:
                time.sleep(5)
    except ClientError as err:
        print("Unexpected error in attaching ENI to EC2 %s" % err) 
    time.sleep(5)
    arp_eth_status(index)
    attach_ni_ec2_time = time.time()
    print("attach_ni_ec2_time elapsed", attach_ni_ec2_time - start_time)

if __name__ == "__main__":
    result = get_interface_attr(NODE_DNS)  
    eni = create_network_interface(result)
    deattach_ni_ec2_if_atatched(result['INSTANCE_ID'],eni,FORCE)
    total_time = time.time()
    print("Total Program Execution Time ", total_time - start_time)

