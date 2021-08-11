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
## GET_KUBECONFIG                        ##
###########################################

cat > /usr/bin/get_kubeconfig << EOF
#!/usr/bin/env bash
# make .kube for config
mkdir -p /home/ec2-user/.kube
# error if s3 file fails / if file doesnt exist
set -e
# download kubeconfig from S3
aws s3 cp s3://${bucket_name}/kubeconfig_${team}-eks-cluster.gpg /tmp/kubeconfig.gpg
# decrypt it using the passphrase
gpg -d --batch --passphrase ${passphrase} /tmp/kubeconfig.gpg > /home/ec2-user/.kube/config

EOF

chmod +x /usr/bin/get_kubeconfig

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
## Kubeflow setup script                 ##
###########################################

cat > /usr/bin/setup_kubeflow << EOF
#!/usr/bin/env bash
cd /tmp

# make kfctl yaml file
echo "making setup folder"
echo "making setup folder" > /var/log/setup_kubeflow.log
mkdir ${team}-eks-cluster && cd ${team}-eks-cluster
echo "getting base config"
echo "getting base config" > /var/log/setup_kubeflow.log
wget -O kfctl_aws.yaml https://raw.githubusercontent.com/kubeflow/manifests/v1.2-branch/kfdef/kfctl_aws.v1.2.0.yaml

# fix a aws bug
aws configure set default.region ${aws_region}

# edit the yaml
echo "editing config"
echo "editing config" > /var/log/setup_kubeflow.log
# edit region
sed -i 's/us-west-2/${aws_region}/g' kfctl_aws.yaml
# edit pod policy
sed -i 's/enablePodIamPolicy/#enablePodIamPolicy/g' kfctl_aws.yaml
echo "deploying kubeflow from config"
echo "deploying kubeflow from config" > /var/log/setup_kubeflow.log
# deploy kubeflow
kfctl apply -V -f kfctl_aws.yaml
echo "done!"
echo "done!" > /var/log/setup_kubeflow.log

EOF

chmod +x /usr/bin/setup_kubeflow


###########################################
## Kubeflow and kubeconfig auto setup    ##
###########################################


cat > /usr/bin/auto_setup << EOF
#!/usr/bin/env bash

# kubectl
# try to get the kubeconfig from S3
# if it fails, try again in 60s
echo "setting up kubeflow and kubeconfig"
echo "setting up kubeflow and kubeconfig" > /var/log/auto_setup.log
count=1
while [ \$count -le 10 ]
do
  ((count++))
  if [ \$count -eq 10 ]
  then
    echo "couldnt get kubeconfig after 10 attempts skipping"
    echo "couldnt get kubeconfig after 10 attempts skipping" > /var/log/auto_setup.log
    break
  fi
  # try to get kubeconfig
  /usr/bin/get_kubeconfig
  # if it worked, exit loop
  ret=\$?
  if [ \$ret -eq 0 ]; then
    echo "setup kubeconfig"
    echo "setup kubeconfig" > /var/log/auto_setup.log
    break
  fi
  # if failed to get kubeconfig, wait and try again
  echo "failed to get kubeconfig, waiting 60s and trying again"
  echo "failed to get kubeconfig, waiting 60s and trying again" > /var/log/auto_setup.log
  sleep 60
done

echo "checking if kubeflow is already running"
echo "checking if kubeflow is already running" > /var/log/auto_setup.log

# check if kubeflow is already existing
kubectl get namespace | grep kubeflow
ret=\$?
# if kubeflow namespace is found, exit
if [ \$ret -eq 0 ]; then
  echo "kubeflow already deployed"
  echo "kubeflow already deployed" > /var/log/auto_setup.log
  exit 0
fi
echo "deploying kubeflow in 120s"
echo "deploying kubeflow in 120s" > /var/log/auto_setup.log
sleep 120

echo "deploying"
echo "deploying" > /var/log/auto_setup.log
# kubeflow is not yet set up
# set it up via setup_kubeflow command
/usr/bin/setup_kubeflow

EOF

chmod +x /usr/bin/auto_setup



###########################################
## Kubeflow proxy background script      ##
###########################################

cat > /usr/bin/route_kubeflow << EOF
#!/usr/bin/env bash

# while true
#   if istio-ingress-gateway pod exists
#      if proxy not running
#          wait 30s then start port forward
#       else
#         shouldnt be here, but exit 
#   # are only here if gateway pod is gone / kubeflow not set up yet
#   wait 60s for kubeflow to be started

# below is 0 if ingress-gateway pod exists, 1 if not 
# kubectl get pods --namespace istio-system | grep ingressgateway


# if below isnt 0, then proxy is running
# ps -ef | grep port-forward | grep ingressgateway | grep 3100 | wc -l


# wait for pod to come online fully, just in case
# sleep 60
# start proxy to 3100 of the ingress gateway
# kubectl port-forward pods/$(kubectl get pods --namespace istio-system | grep ingressgateway | cut -d" " -f 1) 3100:80 --namespace istio-system > /dev/null 2&>1

echo "starting route_kubeflow"
echo "starting route_kubeflow" > /home/ec2-user/route.log

# implimentation
while :
do

  kubectl get pods --namespace istio-system | grep ingressgateway
  ret=\$?
  if [ \$ret -eq 0 ]; then
    # kubeflow has been deployed and the pod exists
    echo "kubeflow deployed"
    echo "kubeflow deployed" > /home/ec2-user/route.log

    # check if the proxy is already running / if this exec has already been called
    ret=\$(ps -ef | grep port-forward | grep ingressgateway | grep 3100 | wc -l)
    if [ \$ret -eq 0 ]; then
      # proxy isnt yet running
      echo "proxy not yet running"
      echo "proxy not yet running" > /home/ec2-user/route.log

      # wait for pod to come online fully, just in case
      sleep 60
      # start proxy to 3100 of the ingress gateway
      nohup kubectl port-forward pods/\$(kubectl get pods --namespace istio-system | grep ingressgateway | cut -d" " -f 1) 3100:80 --namespace istio-system > /dev/null 2&>1 &
      echo "proxy started"
      echo "proxy started" > /home/ec2-user/route.log
      echo "connect to localhost:3100 to connect to kubeflow"
      exit 0
    else
      # proxy is already running
      echo "proxy already running"
      echo "proxy already running" > /home/ec2-user/route.log
      echo "connect to localhost:3100 to connect to kubeflow"
      exit 0
    fi
    
  fi

  # wait for pod to exist / kubeflow to be set up by a user
  echo "waiting for kubeflow to start"
  echo "waiting for kubeflow to start" > /home/ec2-user/route.log
  sleep 60

done

EOF

chmod +x /usr/bin/route_kubeflow





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



# set up the auto setup as ec2 user
sudo -u ec2-user bash /usr/bin/auto_setup


echo "nick"

# start kubeflow routing when bastion starts as ec2-user
nohup /usr/bin/route_kubeflow > /tmp/routelogs 2&>1 &

nohup bash -c "sleep 600 & echo ahoy > /var/log/ahoy"
