#!/bin/bash
touch health-check.log

if [ `cat health-check.log | wc -l` -gt 6000 ]
then
rm -rf /health-check.log
fi

if ping -w 10 -c 1 ${FLOATING_IP} > /dev/null;
then
echo "`date` --> Floating IP is ${FLOATING_IP} Reachable" >> /health-check.log
else
echo "`date` --> Floating IP ${FLOATING_IP} is NOT Reachable..Trying to attach floating ip" >> /health-check.log
python3.8 eip.py True >> /health-check.log

if ping -w 10 -c 1 ${FLOATING_IP} > /dev/null;
then
echo "`date` --> Floating IP is ${FLOATING_IP} Reachable again" >> /health-check.log
else
echo "`date` --> Floating IP ${FLOATING_IP} is Still NOT Reachable. Exiting..." >> /health-check.log
exit 1
fi

fi