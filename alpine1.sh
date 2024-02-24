#!/bin/ash
# ALPINE SETUP SCRIPT FIRST RUN - https://wiki.alpinelinux.org/wiki/Alpine_setup_scripts

# Update package list and upgrade the system
echo "Updating and upgrading the system..."
apk update && apk upgrade

# Install sudo
echo "Installing sudo..."
apk add sudo

# Install necessary dependencies for Docker
echo "Installing dependencies..."
apk add curl ca-certificates libseccomp

# Remove existing Docker packages if they exist
echo "Removing existing Docker packages..."
apk del docker docker-engine docker.io containerd runc

# Install Docker and its dependencies
echo "Installing Docker..."
apk add docker docker-compose && \
rc-update add docker boot && \
service docker start

# Install OpenSSH and ensure it starts on boot
echo "Installing and configuring OpenSSH..."
apk add openssh && \
rc-update add sshd && \
service sshd start

# Install open-vm-tools for VMware virtual machines
echo "Installing open-vm-tools..."
apk add open-vm-tools && \
rc-update add open-vm-tools boot && \
service open-vm-tools start

# Configure the firewall (assuming you're using iptables)
echo "Configuring the firewall for SSH..."
apk add iptables && \
iptables -A INPUT -p tcp --dport 22 -j ACCEPT && \
/etc/init.d/iptables save

# Create a new user with sudo privileges
echo "Creating a new user 'user' with sudo privileges..."
adduser -D user && \
echo "user:password" | chpasswd && \
echo "user ALL=(ALL) ALL" >> /etc/sudoers

# Perform general system cleanup
echo "Performing general system cleanup..."
apk cache clean


echo "Setup complete!"
