#!/bin/bash

clear

######################################################
# Define ANSI escape sequence for green and red font #
######################################################
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'

########################################################
# Define ANSI escape sequence to reset font to default #
########################################################
NC='\033[0m'

#################
# Intro message #
#################
echo
echo
echo -e "${GREEN} Script for creating ProxMox Debian server Template ${NC}"

sleep 1 # delay for 1 seconds
echo

echo -e "${GREEN}REMEMBER:${NC}"
echo
sleep 0.5 # delay for 0.5 seconds

echo -e "${GREEN} - You should be on a clean Debian server VM before running this script ${NC}"
echo -e "${GREEN} - For package 'cloud-initramfs-growroot' to work (ProxMox > VM > Hardware > Hard Disk > Disk Action > Resize), ${NC}"
echo -e "${GREEN}   VM should be created without SWAP Partition during install process. ${NC}"
echo -e "${GREEN} - Bastion Host | Jump Server Private SSH key shoud be already copied on this machine!!! ${NC}"

sleep 1 # delay for 1 seconds
echo

######################################
# Prompt user to confirm script start#
######################################
while true; do
    echo -e "${GREEN}Start Linux Server Hardening? (y/n) ${NC}"
    read choice

    # Check if user entered "y" or "Y"
    if [[ "$choice" == [yY] ]]; then

        # Execute first command and echo -e message when done
        echo -e "${GREEN}Updating the apt package index and installing necessary packages ${NC}"
        sleep 1.5 # delay for 1.5 seconds
        sudo apt-get update
        sudo apt-get install -y \
			ufw \
			git \
			wget \
			curl \
			tmux \
			gnupg2 \
			argon2 \
			fail2ban \
			cloud-init \
			lsb-release \
			gnupg-agent \
			libpam-tmpdir \
			bash-completion \
			fonts-powerline \
			ca-certificates \
			qemu-guest-agent \
			apt-transport-https \
			unattended-upgrades \
			cloud-initramfs-growroot \
			software-properties-common
        echo -e "${GREEN}Done. ${NC}"
        sleep 1 # delay for 1 second
        echo
        break

    # If user entered "n" or "N", exit the script
    elif [[ "$choice" == [nN] ]]; then
        echo -e "${RED}Aborting script. ${NC}"
        exit

    # If user entered anything else, ask them to correct it
    else
        echo -e "${YELLOW}Invalid input. Please enter 'y' or 'n'.${NC}"
    fi
done

######################################################################
# Creating a backup of files before making changes using the script. #
######################################################################

sudo cp /etc/apt/apt.conf.d/50unattended-upgrades /etc/apt/apt.conf.d/50unattended-upgrades.bak

sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

sudo cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak

sudo cp /etc/fstab /etc/fstab.bak

sudo cp /etc/sysctl.conf /etc/sysctl.conf.bak

sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.bak

sudo cp /etc/sysctl.conf /etc/sysctl.bak

####################
# Create SWAP file #
####################
  echo -e "${GREEN}Creating SWAP file${NC}"
  # Create empty file
  sudo fallocate -l 2G /swapfile 
  # Set permissions
  sudo chmod 600 /swapfile
  # Set up swap area
  sudo mkswap /swapfile
  # Activate swap area
  sudo swapon /swapfile
  # Add entry to /etc/fstab to make swap permanent
  echo '/swapfile   none    swap    sw    0   0' | sudo tee -a /etc/fstab

  echo -e "${GREEN}Done.${NC}"
  sleep 1 # delay for 1 seconds
  echo

############################################
# Automatically enable unnatended-upgrades #
############################################
  echo -e "${GREEN}Enabling unnatended-upgrades ${NC}"
  echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | sudo debconf-set-selections && sudo dpkg-reconfigure -f noninteractive unattended-upgrades

  sleep 1.5 # delay for 1.5 seconds

  # Define the file path
  FILEPATH="/etc/apt/apt.conf.d/50unattended-upgrades"

  # Uncomment the lines
  sudo sed -i 's|//Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";|Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";|g' $FILEPATH
  sudo sed -i 's|//Unattended-Upgrade::Remove-New-Unused-Dependencies "true";|Unattended-Upgrade::Remove-New-Unused-Dependencies "true";|g' $FILEPATH
  sudo sed -i 's|//Unattended-Upgrade::Remove-Unused-Dependencies "false";|Unattended-Upgrade::Remove-Unused-Dependencies "true";|g' $FILEPATH
  sudo sed -i 's|//Unattended-Upgrade::Automatic-Reboot "false";|Unattended-Upgrade::Automatic-Reboot "false";|g' $FILEPATH
  sudo sed -i 's|//Unattended-Upgrade::Automatic-Reboot-Time "02:00";|Unattended-Upgrade::Automatic-Reboot-Time "02:00";|g' $FILEPATH

  echo -e "${GREEN}Done. ${NC}"
  sleep 1 # delay for 1 seconds
  echo

#################
# Seting up UFW #
#################
  echo -e "${GREEN}Seting up UFW${NC}"
  # Limit SSH to Port 22/tcp
  sudo ufw limit 22/tcp comment "SSH"
  # Enable UFW without prompt
  sudo ufw --force enable
  # Global blocks
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw reload

  echo -e "${GREEN}Done.${NC}"
  sleep 2 # delay for 2 seconds
  echo

######################
# Seting up Fail2Ban #
######################
  echo -e "${GREEN}Seting up Fail2Ban ${NC}"
  # To preserve your custom settings...
  sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
  # Fixing Debian bug
  sudo sed -i 's|backend = auto|backend = systemd|g' /etc/fail2ban/jail.local

  echo

  echo -e "${GREEN}Enabling Fail2Ban protection for the SSH service ${NC}"
  # Set the path to the sshd configuration file
  config_file="/etc/fail2ban/jail.local"
  # Use awk to add the line "enabled = true" below the second line containing "[sshd]" (first is a comment)
  sudo awk '/\[sshd\]/ && ++n == 2 {print; print "enabled = true"; next}1' "$config_file" > temp_file
  # Overwrite the original configuration file with the modified one
  sudo mv temp_file "$config_file"
  # Change bantime to 60m
  sudo sed -i 's|bantime  = 10m|bantime  = 15m|g' /etc/fail2ban/jail.local
  # Change maxretry to 3
  sudo sed -i 's|maxretry = 5|maxretry = 3|g' /etc/fail2ban/jail.local

  echo -e "${GREEN}Done. ${NC}"
  sleep 1.5 # delay for 1.5 seconds
  echo

##########################
# Securing Shared Memory #
##########################
  echo -e "${GREEN}Securing Shared Memory${NC}"
  # Define the line to append
  LINE="none /run/shm tmpfs defaults,ro 0 0"
  # Append the line to the end of the file
  echo "$LINE" | sudo tee -a /etc/fstab > /dev/null

  echo -e "${GREEN}Done.${NC}"
  sleep 1.5 # delay for 1.5 seconds
  echo

###############################
# Setting up system variables #
###############################
  echo -e "${GREEN}Setting up system variables ${NC}"

  # Define the file path
  FILEPATH="/etc/sysctl.conf"

  # Uncomment the next two lines to enable Spoof protection (reverse-path filter)
  # Turn on Source Address Verification in all interfaces to
  # prevent some spoofing attacks
  sudo sed -i 's|#net.ipv4.conf.default.rp_filter=1|net.ipv4.conf.default.rp_filter=1|g' $FILEPATH
  sudo sed -i 's|#net.ipv4.conf.all.rp_filter=1|net.ipv4.conf.all.rp_filter=1|g' $FILEPATH

  # Do not accept ICMP redirects (prevent MITM attacks)
  sudo sed -i 's|#net.ipv4.conf.all.accept_redirects = 0|net.ipv4.conf.all.accept_redirects = 0|g' $FILEPATH
  sudo sed -i 's|#net.ipv6.conf.all.accept_redirects = 0|net.ipv6.conf.all.accept_redirects = 0|g' $FILEPATH

  # Do not send ICMP redirects (we are not a router)
  sudo sed -i 's|#net.ipv4.conf.all.send_redirects = 0|net.ipv4.conf.all.send_redirects = 0|g' $FILEPATH

  sudo sed -i 's|#net.ipv4.conf.all.accept_source_route = 0|net.ipv4.conf.all.accept_source_route = 0|g' $FILEPATH
  sudo sed -i 's|#net.ipv6.conf.all.accept_source_route = 0|net.ipv6.conf.all.accept_source_route = 0|g' $FILEPATH

  # Log Martian Packets
  sudo sed -i 's|#net.ipv4.conf.all.log_martians = 1|net.ipv4.conf.all.log_martians = 1|g' $FILEPATH

  # Check if the last command was successful
  if [ $? -eq 0 ]; then
      echo -e "${GREEN}Configuration updated successfully. Reloading sysctl...${NC}"
      sudo sysctl -p
  else
      echo -e "${RED}Error occurred during configuration update.${NC}"
  fi

  echo -e "${GREEN}Done. ${NC}"
  sleep 1.5 # delay for 1.5 seconds
  echo

#################################
# Locking root account password #
#################################
  echo -e "${GREEN}Locking root account password${NC}"
  sudo passwd -l root

  echo -e "${GREEN}Done.${NC}"
  sleep 1.5 # delay for 1.5 seconds
  echo

############################
# Setting up SSH variables #
############################
  echo -e "${GREEN}Setting up SSH variables ${NC}"

  # Define the file path
  FILEPATH="/etc/ssh/sshd_config"

   # ... enable challenge-response passwords ...
  sudo sed -i 's|KbdInteractiveAuthentication no|#KbdInteractiveAuthentication no|g' $FILEPATH

  # Changing Log level (default INFO)
  sudo sed -i 's|#LogLevel INFO|LogLevel VERBOSE|g' $FILEPATH

  # Determines whether the root user can log in to the system remotely via SSH
  sudo sed -i 's|#PermitRootLogin prohibit-password|PermitRootLogin no|g' $FILEPATH

  # Enforce additional security restrictions
  sudo sed -i 's|#StrictModes yes|StrictModes yes|g' $FILEPATH

  # Limit number of authentication attempts to prevent brute-force attacks
  sudo sed -i 's|#MaxAuthTries 6|MaxAuthTries 3|g' $FILEPATH

  # Maximum number of Sessions
  sudo sed -i 's|#MaxSessions 10|MaxSessions 2|g' $FILEPATH

  # Disable empty passwords and weak passwords
  sudo sed -i 's|#IgnoreRhosts yes|IgnoreRhosts yes|g' $FILEPATH

  # Disable empty passwords and weak passwords
  sudo sed -i 's|#PasswordAuthentication yes|PasswordAuthentication no|g' $FILEPATH

  # Disable empty passwords and weak passwords
  sudo sed -i 's|#PermitEmptyPasswords no|PermitEmptyPasswords no|g' $FILEPATH

###  # Disable X11 forwarding (unless you need it)
###  sudo sed -i 's|X11Forwarding yes|#X11Forwarding yes|g' $FILEPATH

  # UsePAM
  sudo sed -i 's|UsePAM yes|UsePAM no|g' $FILEPATH

###  # Disable SSH agent forwarding (unless you need it)
###  sudo sed -i 's|#AllowAgentForwarding yes|AllowAgentForwarding no|g' $FILEPATH

  # Use GSSAPIAuthentication (allows for IP address-based authentication in SSH)
  sudo sed -i 's|#GSSAPIAuthentication no|GSSAPIAuthentication no|g' $FILEPATH

  # Update SSH settings to use stronger encryption and key exchange algorithms
  sudo sed -i '/# Ciphers and keying/a Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' $FILEPATH
  sudo sed -i '/chacha20-poly1305/a KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256' $FILEPATH

  # It is set by default but Lynus will flag it if it isn't specified
  sudo sed -i '/curve25519-sha256/a Protocol 2' $FILEPATH
  
  echo -e "${GREEN}Done.${NC}"
  sleep 1.5 # delay for 1.5 seconds
  echo

#######################################################
# Disabling ChallengeResponseAuthentication explicitly #
#######################################################
  echo -e "${GREEN}Disabling ChallengeResponseAuthentication ${NC}"
  # Define the line to append
  LINE="ChallengeResponseAuthentication no"

  # Append the line to the end of the file
  echo "$LINE" | sudo tee -a /etc/ssh/sshd_config > /dev/null

  echo -e "${GREEN}Done. ${NC}"
  sleep 1 # delay for 1 seconds
  echo

#############################################
# Allow SSH only for the current Linux user #
#############################################
  echo -e "${GREEN}Allowing SSH only for the current Linux user ${NC}"
  # Get the current Linux user
  user=$(whoami)

  # Append the user's username to /etc/ssh/sshd_config
  echo "AllowUsers $user" | sudo tee -a /etc/ssh/sshd_config >/dev/null
  sudo systemctl restart ssh

  echo -e "${GREEN}Done. ${NC}"
  sleep 1 # delay for 1 seconds
  echo

################
# Restart sshd #
################
  echo -e "${GREEN}Restarting sshd${NC}"
  sudo systemctl restart sshd

  echo -e "${GREEN}Done.${NC}"
  sleep 1 # delay for 1 seconds
  echo

################
# Disable IPv6 #
################
while true; do
    # Prompt the user for action
    echo -e "${GREEN}Do you want to disable IPv6? (y/n) ${NC}"
    read choice
    case $choice in
        y|Y)
            echo -e "${GREEN}Disabling IPv6... ${NC}"
            # Temporarily disable IPv6
            sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null
            sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null

			echo ""

            # Persistently disable IPv6
            echo "net.ipv6.conf.all.disable_ipv6=1" | sudo tee -a /etc/sysctl.conf
            echo "net.ipv6.conf.default.disable_ipv6=1" | sudo tee -a /etc/sysctl.conf
			
			echo ""

            echo -e "${GREEN}IPv6 has been disabled and the setting is now persistent. ${NC}"
            break
            ;;
        n|N)
            echo -e "${GREEN}IPv6 will not be disabled. ${NC}"
            break
            ;;
        *)
            echo -e "${YELLOW}Invalid input. Please enter 'y' or 'n'. ${NC}"
            ;;
    esac
done

echo
sleep 1.5 # delay for 1.5 seconds

#########################
# Fix machine-id change #
#########################
  # Fix machine-id change
  echo -e "${GREEN}Setting up machine-id change when cloning Template to VM${NC}"
  sleep 1.5 # delay for 1.5 seconds
  sudo truncate -s 0 /etc/machine-id
  sudo rm /var/lib/dbus/machine-id
  sudo ln -s /etc/machine-id /var/lib/dbus/machine-id
  #ls -l /var/lib/dbus/machine-id

  echo -e "${GREEN}Done.${NC}"
  sleep 1 # delay for 1 seconds
  echo

###########################
# Clear old SSH host keys #
###########################
  # Delete old SSH host keys
  echo -e "${GREEN}Deleting old SSH host keys ${NC}"
  sleep 1 # delay for 1 seconds
  sudo rm /etc/ssh/ssh_host_*

  echo -e "${GREEN}Done.${NC}"
  sleep 1 # delay for 1 seconds
  echo

############################
# Clear bash shell history #
############################
  # Clear bash shell history
  history -c

############
# Reminder #
############
  username=$(whoami)
  ip_address=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{ print $2}' | cut -d/ -f1)
  #command that shows only first identified ip v4 address
  #ip_address=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{ print $2}' | cut -d/ -f1 | head -n 1)
  echo -e "${GREEN}Everything is set. New Debian server Template VM is ready!${NC}"
  
  sleep 1.5 # delay for 1.5 seconds

  echo
  echo -e "${GREEN}Please DO NOT forget:${NC}"
  echo
  echo -e "${GREEN} - Add CloudInit drive to VM: VM > Hardware > Add > Cloudinit drive ${NC}"
  echo -e "${GREEN} - Add login details to Cloudinit drive: VM > Cloudinit > Add: User, Password ${NC}"
  echo -e "${GREEN} - Regenerate Image: VM > Cloudinit > Regenerate Image ${NC}"
  echo -e "${GREEN} - Convert VM to Template: VM > Convert to template ${NC}"
  echo
  echo -e "${GREEN}Use Bastion Host | Jump Server to SSH to this VM using the command: ${NC}"
  echo
  echo -e "${RED}ssh username@ipaddress${NC}"
  echo  
  echo -e "${GREEN}Use Bastion Host | Jump Server to to JUMP to this VM from your local machine using the command: ${NC}"
  echo -e "${GREEN}(irst transfer SSH Public Key form your local machine to cloned VM using Bastion)${NC}"
  echo  
  echo -e "${RED}ssh -J username@bastion-ipaddress:port-number username@ipaddress${NC}"

  echo

  sleep 1 # delay for 1 seconds

####################################
# Seting up bash and tmux dotfiles #
####################################
  echo -e "${GREEN}Seting up bash and tmux dotfiles ${NC}"
#  user=$(whoami)
#  git clone https://github.com/vdarkobar/dotfiles.git
#  sudo chmod +x /home/${user}/dotfiles/install.sh
#  sudo chmod +x /home/${user}/dotfiles/uninstall.sh

  cd ~ && \
  git clone https://github.com/vdarkobar/dotfiles.git && \
  cd dotfiles && \
  chmod +x install.sh && chmod +x uninstall.sh && \
  ./install.sh

  cd ~
  
  # Find all dot files then if the original file exists, create a backup
  # Once backed up to {file}.dtbak symlink the new dotfile in place

  echo -e "${GREEN}Done. ${NC}"
  sleep 1 # delay for 1 seconds
  echo

###################################################################
# Ask user to power off for conversion to template or exit script #
###################################################################

while true; do
  echo -e "${GREEN}Power off VM to convert to template now (recommended) or exit the script? (poweroff/exit): ${NC}"
  read action

  case $action in
    poweroff)
      echo -e "${GREEN}This machine will power off in 2 seconds.${NC}"
      sleep 2 # delay for 2 seconds
      sudo apt clean && sudo apt autoremove && sudo poweroff
      break # Exit the loop after initiating power off
      ;;
    exit)
      echo -e "${RED}Exiting script without powering off. Remember to power off before conversion!${NC}"
      exit 0
      ;;
    *)
      echo -e "${YELLOW}Invalid input. Please enter 'poweroff' or 'exit'.${NC}"
      ;;
  esac
done

