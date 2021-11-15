#!/bin/bash -x
yum -y update --security

##########################
## ENABLE SSH RECORDING ##
##########################

# Create a new folder for the log files
mkdir /var/log/bastion

# Allow ec2-user only to access this folder and its content
chown ec2-user:ec2-user /var/log/bastion
chmod -R 770 /var/log/bastion
setfacl -Rdm other:0 /var/log/bastion

# Update sshd default port to public_ssh_port
sed -i "s/#Port 22/Port ${public_ssh_port}/g" /etc/ssh/sshd_config

# Make OpenSSH execute a custom script on logins
echo -e "\\nForceCommand /usr/bin/bastion/shell" >> /etc/ssh/sshd_config

# Block some SSH features that bastion host users could use to circumvent the solution
awk '!/X11Forwarding/' /etc/ssh/sshd_config > temp && mv temp /etc/ssh/sshd_config
echo "X11Forwarding no" >> /etc/ssh/sshd_config

mkdir /usr/bin/bastion

cat > /usr/bin/bastion/shell << 'EOF'

# Check that the SSH client did not supply a command
if [[ -z $SSH_ORIGINAL_COMMAND ]]; then

  # The format of log files is /var/log/bastion/YYYY-MM-DD_HH-MM-SS_user
  LOG_FILE="`date --date="today" "+%Y-%m-%d_%H-%M-%S"`_`whoami`"
  LOG_DIR="/var/log/bastion/"

  # Print a welcome message
  echo ""
  echo "NOTE: This SSH session will be recorded"
  echo "AUDIT KEY: $LOG_FILE"
  echo ""

  # I suffix the log file name with a random string. I explain why later on.
  SUFFIX=`mktemp -u _XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`

  # Wrap an interactive shell into "script" to record the SSH session
  script -qf --timing=$LOG_DIR$LOG_FILE$SUFFIX.time $LOG_DIR$LOG_FILE$SUFFIX.data --command=/bin/bash

else

  # If the module consumer wants to allow remote commands (for ansible or other) then allow that command through.
  if [ "${allow_ssh_commands}" == "True" ]; then
    exec /bin/bash -c "$SSH_ORIGINAL_COMMAND"
  else
    # The "script" program could be circumvented with some commands (e.g. bash, nc).
    # Therefore, I intentionally prevent users from supplying commands.

    echo "This bastion supports interactive sessions only. Do not supply a command"
    exit 1
  fi
fi

EOF

# Make the custom script executable
chmod a+x /usr/bin/bastion/shell

# Bastion host users could overwrite and tamper with an existing log file using "script" if
# they knew the exact file name. I take several measures to obfuscate the file name:
# 1. Add a random suffix to the log file name.
# 2. Prevent bastion host users from listing the folder containing log files. This is done
#    by changing the group owner of "script" and setting GID.
chown root:ec2-user /usr/bin/script
chmod g+s /usr/bin/script

# 3. Prevent bastion host users from viewing processes owned by other users, because the log
#    file name is one of the "script" execution parameters.
mount -o remount,rw,hidepid=2 /proc
awk '!/proc/' /etc/fstab > temp && mv temp /etc/fstab
echo "proc /proc proc defaults,hidepid=2 0 0" >> /etc/fstab

# Restart the SSH service to apply /etc/ssh/sshd_config modifications.
service sshd restart



#########################################
## Install kubectl, aws-iam-auth and eksctl
#########################################

# kubectl
curl -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.20.4/2021-04-12/bin/linux/amd64/kubectl
chmod +x ./kubectl
mv kubectl /usr/bin

# eksctl
curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
sudo mv /tmp/eksctl /usr/local/bin

# aws-iam-auth
curl -o aws-iam-authenticator https://amazon-eks.s3.us-west-2.amazonaws.com/1.19.6/2021-01-05/bin/linux/amd64/aws-iam-authenticator
chmod +x ./aws-iam-authenticator
mv aws-iam-authenticator /usr/bin


############################
## EXPORT LOG FILES TO S3 ##
############################

cat > /usr/bin/bastion/sync_s3 << 'EOF'
#!/usr/bin/env bash

# Copy log files to S3 with server-side encryption enabled.
# Then, if successful, delete log files that are older than a day.
LOG_DIR="/var/log/bastion/"
aws s3 cp $LOG_DIR s3://${bucket_name}/logs/ --sse --region ${aws_region} --recursive && find $LOG_DIR* -mtime +1 -exec rm {} \;

EOF

chmod 700 /usr/bin/bastion/sync_s3

#######################################
## SYNCHRONIZE USERS AND PUBLIC KEYS ##
#######################################

# Bastion host users should log in to the bastion host with their personal SSH key pair.
# The public keys are stored on S3 with the following naming convention: "username.pub".
# This script retrieves the public keys, creates or deletes local user accounts as needed,
# and copies the public key to /home/username/.ssh/authorized_keys

cat > /usr/bin/bastion/sync_users << 'EOF'
#!/usr/bin/env bash

# The file will log user changes
LOG_FILE="/var/log/bastion/users_changelog.txt"

# The function returns the user name from the public key file name.
# Example: public-keys/sshuser.pub => sshuser
get_user_name () {
  echo "$1" | sed -e "s/.*\///g" | sed -e "s/\.pub//g"
}

# For each public key available in the S3 bucket
aws s3api list-objects --bucket ${bucket_name} --prefix public-keys/ --region ${aws_region} --output text --query 'Contents[?Size>`0`].Key' | tr '\t' '\n' > ~/keys_retrieved_from_s3
while read line; do
  USER_NAME="`get_user_name "$line"`"

  # Make sure the user name is alphanumeric
  if [[ "$USER_NAME" =~ ^[a-z][-a-z0-9]*$ ]]; then

    # Create a user account if it does not already exist
    cut -d: -f1 /etc/passwd | grep -qx $USER_NAME
    if [ $? -eq 1 ]; then
      /usr/sbin/adduser $USER_NAME && \
      mkdir -m 700 /home/$USER_NAME/.ssh && \
      chown $USER_NAME:$USER_NAME /home/$USER_NAME/.ssh && \
      echo "$line" >> ~/keys_installed && \
      echo "`date --date="today" "+%Y-%m-%d %H-%M-%S"`: Creating user account for $USER_NAME ($line)" >> $LOG_FILE
    fi

    # Copy the public key from S3, if an user account was created from this key
    if [ -f ~/keys_installed ]; then
      grep -qx "$line" ~/keys_installed
      if [ $? -eq 0 ]; then
        aws s3 cp s3://${bucket_name}/$line /home/$USER_NAME/.ssh/authorized_keys --region ${aws_region}
        chmod 600 /home/$USER_NAME/.ssh/authorized_keys
        chown $USER_NAME:$USER_NAME /home/$USER_NAME/.ssh/authorized_keys
      fi
    fi

  fi
done < ~/keys_retrieved_from_s3

# Remove user accounts whose public key was deleted from S3
if [ -f ~/keys_installed ]; then
  sort -uo ~/keys_installed ~/keys_installed
  sort -uo ~/keys_retrieved_from_s3 ~/keys_retrieved_from_s3
  comm -13 ~/keys_retrieved_from_s3 ~/keys_installed | sed "s/\t//g" > ~/keys_to_remove
  while read line; do
    USER_NAME="`get_user_name "$line"`"
    echo "`date --date="today" "+%Y-%m-%d %H-%M-%S"`: Removing user account for $USER_NAME ($line)" >> $LOG_FILE
    /usr/sbin/userdel -r -f $USER_NAME
  done < ~/keys_to_remove
  comm -3 ~/keys_installed ~/keys_to_remove | sed "s/\t//g" > ~/tmp && mv ~/tmp ~/keys_installed
fi

EOF

chmod 700 /usr/bin/bastion/sync_users


###########################################
## SETUP_Kube                            ##
###########################################

# wait for services gpg file to be uploaded to S3
# make kubeconfig directory
# download services gpg file
# decrypt the file into a tar archive
# extract the tar archive
# get the kubectl config file 

cat > /usr/bin/setup_kube << EOF
#!/usr/bin/env bash
set -x

# source bashrc to get vars for services setup
source /home/ec2-user/.bashrc

# make .kube for config
mkdir -p /home/ec2-user/.kube

while :
do
  # try to download services file from S3
  aws s3 cp s3://${bucket_name}/${team}-services.tar.gz.gpg /tmp/${team}-services.tar.gz.gpg
  # if it worked, exit loop
  ret=\$?
  if [ \$ret -eq 0 ]; then
    echo "got services"
    echo "got services" >> /tmp/services_setup.log
    break
  fi
  # if failed to get kubeconfig, wait and try again
  echo "failed to get services file, waiting 60s and trying again"
  echo "failed to get services file, waiting 60s and trying again" >> /tmp/services_setup.log
  sleep 60
done


# decrypt it using the passphrase
gpg -d --batch --passphrase ${passphrase} /tmp/${team}-services.tar.gz.gpg > /tmp/${team}-services.tar.gz

# untar
cd /tmp
tar -xvf ${team}-services.tar.gz

# copy kubeconfig into place
cp /tmp/tmp/${team}-services/kubeconfig /home/ec2-user/.kube/config

EOF

chmod +x /usr/bin/setup_kube

###########################################
## SETUP_SEVICES                         ##
###########################################

# cd to services setup
# run entrypoint.sh for all service folders that were included

cat > /usr/bin/setup_services << EOF
#!/usr/bin/env bash
set -x

# source bashrc to get vars for services setup
source /home/ec2-user/.bashrc

# go to services location
cd /tmp/tmp/${team}-services
for d in */ ; do
    cd \$d
    pwd
    # for each service run entrypoint.sh
    # sorted alphabetically
    if test -f "entrypoint.sh"; then
        echo "found service setup entrypoint"
        echo "found service setup entrypoint" >> /tmp/services_setup.log
        # make sure entrypoint is executable
        chmod +x entrypoint.sh
        # run it in current environment
        echo "running entrypoing for \$d"
        echo "running entrypoing for \$d" >> /tmp/services_setup.log
        . ./entrypoint.sh  
    fi
    cd /tmp/tmp/${team}-services

done

echo "services deployed" >> /tmp/services_setup.log

EOF

chmod +x /usr/bin/setup_services


###########################################
## SETUP_CNI                             ##
###########################################

# automates this setup "eks vpc install instructions".txt

cat > /usr/bin/setup_cni << EOF
#!/usr/bin/env bash
set -x

# source bashrc to get vars for services setup
source /home/ec2-user/.bashrc

# location for yaml files to be created
mkdir /tmp/cni
cd /tmp/cni

#install CNI plugin
kubectl apply -f https://raw.githubusercontent.com/aws/amazon-vpc-cni-k8s/release-1.7/config/v1.7/aws-k8s-cni.yaml

#configure Custom networking
#Edit aws-node DaemonSet and add AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG environment variable to the node container spec and set it to true
kubectl set env ds aws-node -n kube-system AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG=true
kubectl describe daemonset aws-node -n kube-system | grep -A5 Environment

#Terminate worker nodes so that Autoscaling launches newer nodes that come bootstrapped with custom network config
INSTANCE_IDS=\$(aws ec2 describe-instances --query 'Reservations[*].Instances[*].InstanceId' --filters "Name=tag-key,Values=eks:cluster-name" "Name=tag-value,Values=\$team*" --output text --region \$region)
echo \$INSTANCE_IDS
for instance in \$INSTANCE_IDS
do
    aws ec2 terminate-instances --instance-ids \$instance --region \$region
done


# wait until all nodes have come back up
sleep 600

# install jq if not already
sudo yum install -y jq


#Create custom resources for each subnet by replacing Subnet and SecurityGroup IDs. Since we created two secondary subnets, we need create two custom resources.
#populate CRD YAML files

# make group1.yaml from subnet 1
echo "apiVersion: crd.k8s.amazonaws.com/v1alpha1
kind: ENIConfig
metadata:
 name: group1-pod-netconfig
spec:
 subnet: ${subnet_one}
 securityGroups:
 - ${security_group}" > group1.yaml


# make group2.yaml from subnet 2
echo "apiVersion: crd.k8s.amazonaws.com/v1alpha1
kind: ENIConfig
metadata:
 name: group2-pod-netconfig
spec:
 subnet: ${subnet_two}
 securityGroups:
 - ${security_group}" > group2.yaml


#add each subnet and security group
kubectl create -f group1.yaml
kubectl create -f group2.yaml


#annotate nodes with custom network config
# this tells each node based on which SG/subnet its in, what its CNI config is
#       kubectl annotate node <nodename>.<region>.compute.internal k8s.amazonaws.com/eniConfig=group1-pod-netconfig
#attach proper node to region associated, for example both are in USEAST1A which corresponds to subnet-0ab2d7841307a2210 and group1.yaml
#this maps to "group1-pod-netconfig" of eniconfig.crd.k8s.amazonaws.com/group1-pod-netconfig configured

# assign zone_one and zone_two vars from subnet ids
zone_one=\$(aws ec2 describe-subnets --subnet-ids ${subnet_one} --region \$region | grep AvailabilityZone | grep -v Id | cut -d'-' -f3 | rev | cut -c4- | rev)
zone_two=\$(aws ec2 describe-subnets --subnet-ids ${subnet_two} --region \$region | grep AvailabilityZone | grep -v Id | cut -d'-' -f3 | rev | cut -c4- | rev)

# for all nodes / output in this cmd output
NODES=\$(kubectl get nodes)
for node in \$NODES
do
    # get the zone that the node is in    
    zone="na"
    echo \$node | grep compute  && export zone=\$(kubectl describe node \$node | grep zone | grep top | cut -d'-' -f3) || echo "" > /dev/null

    # if the output we are iterating over is a valid node, its zone will match one or two
    # and will annotate to the correct one
    if [[ \$zone == \$zone_one ]]
    then
      kubectl annotate node \$node k8s.amazonaws.com/eniConfig=group1-pod-netconfig
    elif [[ \$zone == \$zone_two ]]
    then
      kubectl annotate node \$node k8s.amazonaws.com/eniConfig=group2-pod-netconfig
    else
      echo "not applicable" > /dev/null
    fi
    
done

# TODO automatically do the above section on scaling event


EOF

chmod +x /usr/bin/setup_cni

###########################################
## TERRAFORM                             ##
###########################################


yum install -y yum-utils

yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo

yum -y install terraform

###########################################
## KFCTL                                 ##
###########################################

startdir=$(pwd)
cd /tmp
wget https://github.com/kubeflow/kfctl/releases/download/v1.2.0/kfctl_v1.2.0-0-gbc038f9_linux.tar.gz
tar -xzvf kfctl_v1.2.0-0-gbc038f9_linux.tar.gz
chmod +x kfctl
mv kfctl /usr/bin/
cd $startdir

###########################################
## Helm                                  ##
###########################################

curl https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash


###########################################
## SCHEDULE SCRIPTS AND SECURITY UPDATES ##
###########################################

cat > ~/mycron << EOF
*/5 * * * * /usr/bin/bastion/sync_users
0 0 * * * yum -y update --security
${sync_logs_cron_job}
EOF
crontab ~/mycron
rm ~/mycron


#########################################
## Add Custom extra_user_data_content ##
#######################################

${extra_user_data_content}


########################################
## Set env vars                       ##
########################################

# ensure bashrc is there
sudo -u ec2-user touch /home/ec2-user/.bashrc
# as ec2-user add variables to bashrc
sudo -u ec2-user python - <<EOF

# get vars from terraform
vars = ${bastion_variables}

lines = []

# add export cmds to run on bash init from variables to use
for var,value in zip(vars.keys(),vars.values()):
	lines.append("export {}=\"{}\"\n".format(var,value))

# add line to .bashrc for user to access vars
with open("/home/ec2-user/.bashrc","a") as bashrc:
	for line in lines:
		bashrc.write(line)

EOF

#######################################
## Run service setup                 ##
#######################################

# as ec2-user, setup kube stuff before anything else
# runs as ec2-user in a new bash shell, that will have all vars set
sudo -u ec2-user bash /usr/bin/setup_kube

# as ec2-user, run all cni setup before services
# runs as ec2-user in a new bash shell, that will have all vars set
sudo -u ec2-user bash /usr/bin/setup_cni

# as ec2-user, run all service setup entrypoints
# runs as ec2-user in a new bash shell, that will have all vars set
sudo -u ec2-user bash /usr/bin/setup_services
