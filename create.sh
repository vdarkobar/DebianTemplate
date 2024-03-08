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

sleep 0.5 # delay for 0.5 seconds
echo

echo -e "${GREEN}REMEMBER:${NC}"
echo
sleep 0.5 # delay for 0.5 seconds

echo -e "${GREEN} - You should be on a clean Debian server VM install before running this script ${NC}"
echo -e "${GREEN} - For package${NC} 'cloud-initramfs-growroot' ${GREEN}to work${NC} (ProxMox > VM > Hardware > Hard Disk > Disk Action > Resize)"
echo -e "${GREEN}   VM should be created without${NC} SWAP Partition ${GREEN}during install process. ${NC}"

sleep 0.5 # delay for 0.5 seconds
echo


#######################################
# Prompt user to confirm script start #
#######################################

while true; do
    echo -e "${GREEN}Start Linux Server Hardening?${NC} (yes/no)"
    echo
    read choice
    echo

    # Convert choice to lowercase
    choice=${choice,,} # This makes the script case insensitive

    # Check if user entered "yes"
    if [[ "$choice" == "yes" || "$choice" == "y" ]]; then

        # Execute first command and echo -e message when done
        echo
        echo -e "${GREEN}Updating the apt package index and installing necessary packages ${NC}"
        echo
        sleep 0.5 # delay for 0.5 seconds
        if sudo apt update && sudo apt install -y \
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
            software-properties-common; then
            echo
            echo -e "${GREEN}Done. ${NC}"
        else
            echo -e "${RED}Failed to update or install packages. Please check your connection or package names. ${NC}"
            exit 1
        fi
        sleep 1 # delay for 1 second
        echo
        break

    # If user entered "no"
    elif [[ "$choice" == "no" || "$choice" == "n" ]]; then
        echo -e "${RED}Aborting script. ${NC}"
        exit

    # If user entered anything else, ask them to correct it
    else
        echo -e "${YELLOW}Invalid input. Please enter${NC} 'yes' or 'no'"
    fi
done


######################################################################
# Creating a backup of files before making changes using the script. #
######################################################################

# Copy /etc/apt/apt.conf.d/50unattended-upgrades
if ! sudo cp /etc/apt/apt.conf.d/50unattended-upgrades /etc/apt/apt.conf.d/50unattended-upgrades.bak; then
    echo "Error copying 50unattended-upgrades. Exiting."
    exit 1
fi

# Copy /etc/ssh/sshd_config
if ! sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak; then
    echo "Error copying sshd_config. Exiting."
    exit 1
fi

# Copy /etc/fstab
if ! sudo cp /etc/fstab /etc/fstab.bak; then
    echo "Error copying fstab. Exiting."
    exit 1
fi

# Copy /etc/sysctl.conf (first occurrence, for backup)
if ! sudo cp /etc/sysctl.conf /etc/sysctl.conf.bak; then
    echo "Error copying sysctl.conf for the first backup. Exiting."
    exit 1
fi

# Copy /etc/pam.d/sshd
if ! sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.bak; then
    echo "Error copying sshd in pam.d. Exiting."
    exit 1
fi


####################
# Create SWAP file #
####################

echo -e "${GREEN}Creating SWAP file${NC}"
echo

# Check if a swap file already exists
if swapon --show | grep --quiet "/swapfile"; then
    echo -e "${YELLOW}Swap file already exists. Skipping creation.${NC}"
else
    # Create empty file
    if ! sudo fallocate -l 2G /swapfile; then
        echo -e "${RED}Failed to allocate space for swap file. Exiting.${NC}"
        exit 1
    fi

    # Set permissions
    if ! sudo chmod 600 /swapfile; then
        echo -e "${RED}Failed to set swap file permissions. Exiting.${NC}"
        exit 1
    fi

    # Set up swap area
    if ! sudo mkswap /swapfile; then
        echo -e "${RED}Failed to set up swap space. Exiting.${NC}"
        exit 1
    fi

    # Activate swap area
    if ! sudo swapon /swapfile; then
        echo -e "${RED}Failed to activate swap space. Exiting.${NC}"
        exit 1
    fi

    # Add entry to /etc/fstab to make swap permanent
    if ! echo '/swapfile   none    swap    sw    0   0' | sudo tee -a /etc/fstab > /dev/null; then
        echo -e "${RED}Failed to add swap file to /etc/fstab. Exiting.${NC}"
        exit 1
    fi

    echo
    echo -e "${GREEN}Swap file created and activated successfully.${NC}"
fi

sleep 0.5 # delay for 0.5 seconds
echo


############################################
# Automatically enable unattended-upgrades #
############################################

echo -e "${GREEN}Enabling unattended-upgrades ${NC}"

# Enable unattended-upgrades
if echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | sudo debconf-set-selections && sudo dpkg-reconfigure -f noninteractive unattended-upgrades; then
    echo
    echo -e "${GREEN}Unattended-upgrades enabled successfully.${NC}"
    echo
else
    echo -e "${RED}Failed to enable unattended-upgrades. Exiting.${NC}"
    exit 1
fi

sleep 0.5 # delay for 0.5 seconds

# Define the file path
FILEPATH="/etc/apt/apt.conf.d/50unattended-upgrades"

# Check if the file exists before attempting to modify it
if [ ! -f "$FILEPATH" ]; then
    echo -e "${RED}$FILEPATH does not exist. Exiting.${NC}"
    exit 1
fi

# Uncomment the necessary lines
if sudo sed -i 's|//Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";|Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";|g' $FILEPATH \
   && sudo sed -i 's|//Unattended-Upgrade::Remove-New-Unused-Dependencies "true";|Unattended-Upgrade::Remove-New-Unused-Dependencies "true";|g' $FILEPATH \
   && sudo sed -i 's|//Unattended-Upgrade::Remove-Unused-Dependencies "false";|Unattended-Upgrade::Remove-Unused-Dependencies "true";|g' $FILEPATH \
   && sudo sed -i 's|//Unattended-Upgrade::Automatic-Reboot "false";|Unattended-Upgrade::Automatic-Reboot "true";|g' $FILEPATH \
   && sudo sed -i 's|//Unattended-Upgrade::Automatic-Reboot-Time "02:00";|Unattended-Upgrade::Automatic-Reboot-Time "02:00";|g' $FILEPATH; then
    echo -e "${GREEN}Configuration updated successfully.${NC}"
    echo
else
    echo -e "${RED}Failed to update configuration. Please check your permissions and file paths. Exiting.${NC}"
    exit 1
fi

sleep 0.5 # delay for 0.5 second


##################
# Setting up UFW #
##################

echo -e "${GREEN}Setting up UFW...${NC}"
echo

# Limit SSH to Port 22/tcp
if ! sudo ufw limit 22/tcp comment "SSH"; then
    echo -e "${RED}Failed to limit SSH access. Exiting.${NC}"
    exit 1
fi

# Enable UFW without prompt
if ! sudo ufw --force enable; then
    echo -e "${RED}Failed to enable UFW. Exiting.${NC}"
    exit 1
fi

# Set global rules
if ! sudo ufw default deny incoming || ! sudo ufw default allow outgoing; then
    echo -e "${RED}Failed to set global rules. Exiting.${NC}"
    exit 1
fi

# Reload UFW to apply changes
if ! sudo ufw reload; then
    echo -e "${RED}Failed to reload UFW. Exiting.${NC}"
    exit 1
fi

echo
echo -e "${GREEN}UFW setup completed.${NC}"
sleep 0.5 # delay for 0.5 seconds
echo


#######################
# Setting up Fail2Ban #
#######################

echo -e "${GREEN}Setting up Fail2Ban...${NC}"

# Check if Fail2Ban is installed
if ! command -v fail2ban-server >/dev/null 2>&1; then
    echo -e "${RED}Fail2Ban is not installed. Please install Fail2Ban and try again. Exiting.${NC}"
    exit 1
fi

# To preserve your custom settings...
if ! sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local; then
    echo -e "${RED}Failed to copy jail.conf to jail.local. Exiting.${NC}"
    exit 1
fi

# Copy /etc/fail2ban/jail.local
if ! sudo cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak; then
    echo "Error copying jail.local. Exiting."
    exit 1
fi

# Fixing Debian bug by setting backend to systemd
if ! sudo sed -i 's|backend = auto|backend = systemd|g' /etc/fail2ban/jail.local; then
    echo -e "${RED}Failed to set backend to systemd in jail.local. Exiting.${NC}"
    exit 1
fi

echo -e "${GREEN}Configuring Fail2Ban for SSH protection...${NC}"

# Set the path to the sshd configuration file
config_file="/etc/fail2ban/jail.local"

# Use awk to add "enabled = true" below the second [sshd] line (first is a comment)
if ! sudo awk '/\[sshd\]/ && ++n == 2 {print; print "enabled = true"; next}1' "$config_file" > temp_file || ! sudo mv temp_file "$config_file"; then
    echo -e "${RED}Failed to enable SSH protection. Exiting.${NC}"
    exit 1
fi

# Change bantime to 15m
if ! sudo sed -i 's|bantime  = 10m|bantime  = 15m|g' /etc/fail2ban/jail.local; then
    echo -e "${RED}Failed to set bantime to 15m. Exiting.${NC}"
    exit 1
fi

# Change maxretry to 3
if ! sudo sed -i 's|maxretry = 5|maxretry = 3|g' /etc/fail2ban/jail.local; then
    echo -e "${RED}Failed to set maxretry to 3. Exiting.${NC}"
    exit 1
fi

echo -e "${GREEN}Fail2Ban setup completed.${NC}"
sleep 0.5 # delay for 0.5 seconds
echo


##########################
# Securing Shared Memory #
##########################

echo -e "${GREEN}Securing Shared Memory...${NC}"

# Define the line to append
LINE="none /run/shm tmpfs defaults,ro 0 0"

# Append the line to the end of the file
if ! echo "$LINE" | sudo tee -a /etc/fstab > /dev/null; then
    echo -e "${RED}Failed to secure shared memory. Exiting.${NC}"
    exit 1
fi

sleep 0.5 # delay for 0.5 seconds
echo


###############################
# Setting up system variables #
###############################

echo -e "${GREEN}Setting up system variables...${NC}"
echo

# Define the file path
FILEPATH="/etc/sysctl.conf"

# Modify system variables for security enhancements
if ! sudo sed -i 's|#net.ipv4.conf.default.rp_filter=1|net.ipv4.conf.default.rp_filter=1|g' $FILEPATH \
   || ! sudo sed -i 's|#net.ipv4.conf.all.rp_filter=1|net.ipv4.conf.all.rp_filter=1|g' $FILEPATH \
   || ! sudo sed -i 's|#net.ipv4.conf.all.accept_redirects = 0|net.ipv4.conf.all.accept_redirects = 0|g' $FILEPATH \
   || ! sudo sed -i 's|#net.ipv6.conf.all.accept_redirects = 0|net.ipv6.conf.all.accept_redirects = 0|g' $FILEPATH \
   || ! sudo sed -i 's|#net.ipv4.conf.all.send_redirects = 0|net.ipv4.conf.all.send_redirects = 0|g' $FILEPATH \
   || ! sudo sed -i 's|#net.ipv4.conf.all.accept_source_route = 0|net.ipv4.conf.all.accept_source_route = 0|g' $FILEPATH \
   || ! sudo sed -i 's|#net.ipv6.conf.all.accept_source_route = 0|net.ipv6.conf.all.accept_source_route = 0|g' $FILEPATH \
   || ! sudo sed -i 's|#net.ipv4.conf.all.log_martians = 1|net.ipv4.conf.all.log_martians = 1|g' $FILEPATH; then
    echo -e "${RED}Error occurred during system variable configuration. Exiting.${NC}"
    exit 1
fi

# Reload sysctl with the new configuration
if ! sudo sysctl -p; then
    echo -e "${RED}Failed to reload sysctl configuration. Exiting.${NC}"
    exit 1
fi

sleep 0.5 # delay for 0.5 seconds
echo


#################################
# Locking root account password #
#################################

echo -e "${GREEN}Locking root account password...${NC}"
echo

# Attempt to lock the root account password
if ! sudo passwd -l root; then
    echo -e "${RED}Failed to lock root account password. Exiting.${NC}"
    exit 1
fi

sleep 0.5 # delay for 0.5 seconds
echo


############################
# Setting up SSH variables #
############################

echo -e "${GREEN}Setting up SSH variables...${NC}"

# Define the file path
FILEPATH="/etc/ssh/sshd_config"

# Applying multiple sed operations to configure SSH securely. If any fail, an error message will be shown.
if ! (sudo sed -i 's|KbdInteractiveAuthentication no|#KbdInteractiveAuthentication no|g' $FILEPATH \
    && sudo sed -i 's|#LogLevel INFO|LogLevel VERBOSE|g' $FILEPATH \
    && sudo sed -i 's|#PermitRootLogin prohibit-password|PermitRootLogin no|g' $FILEPATH \
    && sudo sed -i 's|#StrictModes yes|StrictModes yes|g' $FILEPATH \
    && sudo sed -i 's|#MaxAuthTries 6|MaxAuthTries 3|g' $FILEPATH \
    && sudo sed -i 's|#MaxSessions 10|MaxSessions 2|g' $FILEPATH \
    && sudo sed -i 's|#IgnoreRhosts yes|IgnoreRhosts yes|g' $FILEPATH \
    && sudo sed -i 's|#PasswordAuthentication yes|PasswordAuthentication no|g' $FILEPATH \
    && sudo sed -i 's|#PermitEmptyPasswords no|PermitEmptyPasswords no|g' $FILEPATH \
    && sudo sed -i 's|UsePAM yes|UsePAM no|g' $FILEPATH \
    && sudo sed -i 's|#GSSAPIAuthentication no|GSSAPIAuthentication no|g' $FILEPATH \
    && sudo sed -i '/# Ciphers and keying/a Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' $FILEPATH \
    && sudo sed -i '/chacha20-poly1305/a KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256' $FILEPATH \
    && sudo sed -i '/curve25519-sha256/a Protocol 2' $FILEPATH); then
    echo -e "${RED}Failed to configure SSH variables. Exiting.${NC}"
    exit 1
fi

sleep 0.5 # delay for 0.5 seconds
echo


########################################################
# Disabling ChallengeResponseAuthentication explicitly #
########################################################

echo -e "${GREEN}Disabling ChallengeResponseAuthentication...${NC}"

# Define the line to append
LINE="ChallengeResponseAuthentication no"
FILEPATH="/etc/ssh/sshd_config"

# Check if the line already exists to avoid duplications
if grep -q "^$LINE" "$FILEPATH"; then
    echo -e "${YELLOW}ChallengeResponseAuthentication is already set to no.${NC}"
else
    # Append the line to the end of the file
    if ! echo "$LINE" | sudo tee -a $FILEPATH > /dev/null; then
        echo -e "${RED}Failed to disable ChallengeResponseAuthentication. Exiting.${NC}"
        exit 1
    fi
fi

sleep 0.5 # delay for 0.5 seconds
echo


#############################################
# Allow SSH only for the current Linux user #
#############################################

echo -e "${GREEN}Allowing SSH only for the current Linux user...${NC}"

# Get the current Linux user
user=$(whoami)
FILEPATH="/etc/ssh/sshd_config"

# Check if "AllowUsers" is already set for the current user to avoid duplications
if grep -q "^AllowUsers.*$user" "$FILEPATH"; then
    echo -e "${YELLOW}SSH access is already restricted to the current user (${user}).${NC}"
else
    # Append the user's username to /etc/ssh/sshd_config
    if ! echo "AllowUsers $user" | sudo tee -a $FILEPATH >/dev/null; then
        echo -e "${RED}Failed to restrict SSH access to the current user. Exiting.${NC}"
        exit 1
    fi
    # Restart SSH to apply changes
    if ! sudo systemctl restart ssh; then
        echo -e "${RED}Failed to restart SSH service. Exiting.${NC}"
        exit 1
    fi
fi

sleep 0.5 # delay for 0.5 seconds
echo


################
# Restart sshd #
################

echo -e "${GREEN}Restarting sshd...${NC}"

# Attempt to restart the sshd service
if ! sudo systemctl restart sshd; then
    echo -e "${RED}Failed to restart sshd. Please check the service status and logs for more details. Exiting.${NC}"
    exit 1
fi

sleep 0.5 # delay for 0.5 second
echo


################
# Disable IPv6 #
################

while true; do
    # Prompt the user for action
    echo -e "${GREEN}Do you want to disable IPv6?${NC} (yes/no) "
    echo
    read choice
    case $choice in
        y|Y|yes|YES)
            echo
            echo -e "${GREEN}Disabling IPv6...${NC}"
            
            # Temporarily disable IPv6
            if ! sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null \
                || ! sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null; then
                echo -e "${RED}Failed to temporarily disable IPv6. Exiting.${NC}"
                exit 1
            fi

            # Persistently disable IPv6
            if ! echo "net.ipv6.conf.all.disable_ipv6=1" | sudo tee -a /etc/sysctl.conf >/dev/null \
                || ! echo "net.ipv6.conf.default.disable_ipv6=1" | sudo tee -a /etc/sysctl.conf >/dev/null; then
                echo -e "${RED}Failed to persistently disable IPv6. Exiting.${NC}"
                exit 1
            fi
            break
            ;;
        n|N|no|NO)
            # No action taken, IPv6 remains enabled. No explicit success notification here either.
            break
            ;;
        *)
            echo -e "${YELLOW}Invalid input. Please enter${NC} 'yes' or 'no'"
            ;;
    esac
done

echo
sleep 0.5 # delay for 0.5 seconds


#########################
# Fix machine-id change #
#########################

echo -e "${GREEN}Setting up machine-id change when cloning Template to VM...${NC}"
sleep 1.5 # delay for 1.5 seconds

# Clear /etc/machine-id
if ! sudo truncate -s 0 /etc/machine-id; then
    echo -e "${RED}Failed to clear /etc/machine-id. Exiting.${NC}"
    exit 1
fi

# Remove the /var/lib/dbus/machine-id file if it exists
if [ -f /var/lib/dbus/machine-id ]; then
    if ! sudo rm /var/lib/dbus/machine-id; then
        echo -e "${RED}Failed to remove /var/lib/dbus/machine-id. Exiting.${NC}"
        exit 1
    fi
fi

# Create a symbolic link for /var/lib/dbus/machine-id to /etc/machine-id
if ! sudo ln -s /etc/machine-id /var/lib/dbus/machine-id; then
    echo -e "${RED}Failed to link /var/lib/dbus/machine-id to /etc/machine-id. Exiting.${NC}"
    exit 1
fi

sleep 0.5 # delay for 0.5 second
echo


###########################
# Clear old SSH host keys #
###########################

echo -e "${GREEN}Deleting old SSH host keys...${NC}"
sleep 1 # delay for 1 second

# Check if SSH host keys exist before attempting to delete them
if ls /etc/ssh/ssh_host_* 1> /dev/null 2>&1; then
    # Attempt to delete old SSH host keys
    if ! sudo rm /etc/ssh/ssh_host_*; then
        echo -e "${RED}Failed to delete old SSH host keys. Please check your permissions and try again. Exiting.${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}No SSH host keys found to delete.${NC}"
fi

sleep 0.5 # delay for 0.5 second
echo


#####################################
# Setting up bash and tmux dotfiles #
#####################################

echo -e "${GREEN}Setting up bash and tmux dotfiles...${NC}"
echo
sleep 1 # delay for 1 second

# Define user home directory explicitly to avoid any ambiguity and potential permission issues
USER_HOME=$(eval echo ~$USER)

# Clone the dotfiles repository
if ! git clone https://github.com/vdarkobar/dotfiles.git "$USER_HOME/dotfiles"; then
    echo -e "${RED}Failed to clone dotfiles repository. Exiting.${NC}"
    exit 1
fi

# Change directory to the cloned repository
cd "$USER_HOME/dotfiles" || { echo -e "${RED}Failed to navigate to dotfiles directory. Exiting.${NC}"; exit 1; }

# Make installation and uninstallation scripts executable
if ! chmod +x install.sh uninstall.sh; then
    echo -e "${RED}Failed to make scripts executable. Exiting.${NC}"
    exit 1
fi

# Execute the install script
if ! ./install.sh; then
    echo -e "${RED}Failed to execute the install script. Exiting.${NC}"
    exit 1
fi

# Change back to the user home directory
cd "$USER_HOME" || { echo -e "${RED}Failed to return to home directory. Exiting.${NC}"; exit 1; }

sleep 0.5 # delay for 0.5 second
echo


############################
# Clear bash shell history #
############################

  # Clear bash shell history
  history -c


############
# Reminder #
############

# Username
USERNAME=$(whoami)

# Get the primary local IP address of the machine more reliably
LOCAL_IP=$(ip route get 1.1.1.1 | awk '{print $7; exit}')

# Get the short hostname directly
HOSTNAME=$(hostname -s)

# Use awk more efficiently to extract the domain name from /etc/resolv.conf
DOMAIN_LOCAL=$(awk '/^search/ {print $2; exit}' /etc/resolv.conf)

# Directly concatenate HOSTNAME and DOMAIN, leveraging shell parameter expansion for conciseness
LOCAL_DOMAIN="${HOSTNAME}${DOMAIN_LOCAL:+.$DOMAIN_LOCAL}"

  echo -e "${GREEN}Everything is set. New Debian server Template VM is ready!${NC}"
  
  sleep 0.5 # delay for 0.5 seconds

  echo
  echo -e "${GREEN}Please DO NOT forget:${NC}"
  echo
  echo -e "${GREEN} - Add CloudInit drive to VM:${NC} VM > Hardware > Add > Cloudinit drive"
  echo -e "${GREEN} - Add login details to Cloudinit drive:${NC} VM > Cloudinit > Add: User, Password and Bastion/Jump server SSH public key"
  echo -e "${GREEN} - Regenerate Image:${NC} VM > Cloudinit > Regenerate Image"
  echo -e "${GREEN} - Convert VM to Template:${NC} VM > Convert to template"
  echo
  echo -e "${GREEN}Use Bastion Host|Jump Server to SSH to this VM using one of the commands: ${NC}"
  echo
  echo -e "ssh $USERNAME@$LOCAL_IP    |   ssh $USERNAME@$LOCAL_DOMAIN    |   ssh $LOCAL_IP   |   ssh $HOSTNAME"
  echo  
  echo


###################################################################
# Ask user to power off for conversion to template or exit script #
###################################################################

while true; do
  echo -e "${GREEN}Power off VM to convert to template now (recommended) or exit the script?${NC} (poweroff / exit):"
  echo
  read action

  case $action in
    poweroff)
      echo
      echo -e "${GREEN}This machine will power off... ${NC}"
      sleep 1 # delay for 1 seconds
      sudo apt clean && sudo apt autoremove && sudo poweroff
      break # Exit the loop after initiating power off
      ;;
    exit)
      echo
      echo -e "${RED}Exiting script without powering off. Remember to power off before conversion!${NC}"
      exit 0
      ;;
    *)
      echo
      echo -e "${YELLOW}Invalid input. Please enter${NC} 'poweroff' or 'exit'"
      ;;
  esac
done

#####################################
# Remove the Script from the system #
#####################################

echo -e "${RED}This Script Will Self Destruct!${NC}"
echo
# VERY LAST LINE OF THE SCRIPT:
sudo rm "$0"
