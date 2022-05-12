FROM public.ecr.aws/amazonlinux/amazonlinux:latest
RUN amazon-linux-extras install python3.8
WORKDIR /
RUN yum install -y ec2-net-utils && python3.8 -m ensurepip --upgrade && pip3.8 install boto3 && pip3.8 install ipaddress
COPY eip.py . 
COPY health-check.sh .
RUN chmod 754 /eip.py && chmod 754 /health-check.sh
RUN yum install -y unzip
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
RUN unzip awscliv2.zip
RUN ./aws/install && rm -rf awscliv2.zip
