#!/bin/bash

# Exit on any error
set -e

# Check if libguestfs-tools is installed
if ! dpkg -l | grep -q libguestfs-tools; then
    echo "libguestfs-tools is not installed. Installing it now..."
    sudo apt-get update -qq
    sudo apt-get install -y libguestfs-tools
    echo "libguestfs-tools has been installed."
else
    echo "libguestfs-tools is already installed."
fi

# Check for required commands
for cmd in wget qm pvesm sha512sum virt-customize; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[ERROR] Required command '$cmd' is not installed."
        exit 1
    fi
done

# Collect user inputs
while true; do
    read -p "Enter hostname for the VM: " HOSTNAME
    if [[ $HOSTNAME =~ ^[a-zA-Z0-9-]+$ ]] && [[ ! $HOSTNAME =~ ^- ]] && [[ ! $HOSTNAME =~ -$ ]] && [ ${#HOSTNAME} -le 64 ]; then
        break
    else
        echo "[ERROR] Invalid hostname."
    fi
done

# List available storages and select storage
echo "[INFO] Available storages for VM disks:"
pvesm status -content images | awk 'NR>1 && $1 ~ /^[a-zA-Z]/ {print NR-1")", $1}'
while true; do
    read -p "Select storage number: " STORAGE_NUM
    STORAGE=$(pvesm status -content images | awk 'NR>1 && $1 ~ /^[a-zA-Z]/ {print $1}' | sed -n "${STORAGE_NUM}p")
    if [ -n "$STORAGE" ] && pvesm status -content images | grep -q -F "$STORAGE"; then
        break
    else
        echo "[ERROR] Invalid storage selection."
    fi
done

read -p "Enter memory size in MB [default: 4096]: " MEMORY
MEMORY="${MEMORY:-4096}"
read -p "Enter number of cores [default: 4]: " CORES
CORES="${CORES:-4}"

read -p "Enter network bridge [default: vmbr0]: " BRIDGE
BRIDGE="${BRIDGE:-vmbr0}"

# Set variables
VMID=$(pvesh get /cluster/nextid)
DEFAULT_IMAGE_URL="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-nocloud-amd64.qcow2"
IMAGE_NAME="debian-12-nocloud-amd64.qcow2"

# Prompt for custom image URL or use default
read -p "Enter custom image URL or press Enter to use default [$DEFAULT_IMAGE_URL]: " IMAGE_URL
IMAGE_URL="${IMAGE_URL:-$DEFAULT_IMAGE_URL}"

# Download Debian image file to temp folder
TEMP_DIR=$(mktemp -d)
wget --timeout=300 --tries=3 -q --show-progress -O "$TEMP_DIR/$IMAGE_NAME" "$IMAGE_URL"

# Verify checksum
CHECKSUMS_URL="${IMAGE_URL%/*}/SHA512SUMS"
wget -q -O "$TEMP_DIR/SHA512SUMS" "$CHECKSUMS_URL"
(cd "$TEMP_DIR" && grep "$IMAGE_NAME" SHA512SUMS | sha512sum -c --status)

# Prompt for username with validation
while true; do
    read -p "Enter the username for the new user: " username
    if [[ "$username" =~ ^[a-z_][a-z0-9_-]{2,15}$ ]]; then
        break
    else
        echo "Invalid username."
    fi
done

# Prompt for password
while true; do
    read -s -p "Enter the password for the new user: " user_password
    echo
    read -s -p "Confirm the password: " user_password_confirm
    echo
    if [[ "$user_password" == "$user_password_confirm" ]]; then
        break
    else
        echo "Passwords do not match."
    fi
done

# Run virt-customize commands
virt-customize -a "$TEMP_DIR/$IMAGE_NAME" \
    --install qemu-guest-agent,sudo,openssh-server \
    --run-command "echo $HOSTNAME > /etc/hostname" \
    --run-command "sed -i 's/\<localhost\>/$HOSTNAME/g' /etc/hosts" \
    --run-command "useradd -m -s /bin/bash $username" \
    --password "$username:password:$user_password" \
    --run-command "usermod -aG sudo $username" \
    --run-command "passwd -l root" \
    --run-command "echo -n > /etc/machine-id"

# Verify storage space
image_size=$(stat -f --format="%s" "$TEMP_DIR/$IMAGE_NAME")
storage_free=$(pvesm status -content images | awk -v storage="$STORAGE" '$1 == storage {print $4}')
if [ "$image_size" -gt "$storage_free" ]; then
    echo "[ERROR] Insufficient storage space"
    exit 1
fi

# Create VM configuration
qm create "$VMID" \
    --name "$HOSTNAME" \
    --tags "Debian" \
    --memory "$MEMORY" \
    --balloon 512 \
    --cores "$CORES" \
    --sockets 1 \
    --cpu "x86-64-v2-AES" \
    --bios seabios \
    --scsihw virtio-scsi-single \
    --agent enabled=1 \
    --net0 "model=virtio,bridge=$BRIDGE,firewall=1" \
    --description "<div align='center'><img src='https://github.com/vdarkobar/Home-Cloud/blob/main/shared/rsz_debian-logo.png?raw=true'/></div>"

# Configure serial console and VGA (enables xterm.js console for copy/paste)
qm set "$VMID" --serial0 socket
qm set "$VMID" --vga serial0

# Import Debian disk image and set as primary boot disk
qm importdisk "$VMID" "$TEMP_DIR/$IMAGE_NAME" "$STORAGE"
qm set "$VMID" --scsi0 "$STORAGE:vm-$VMID-disk-0,discard=on,ssd=1,cache=none" --boot order=scsi0 --ostype l26

echo "--------------------------------------------"
echo "[INFO] VM creation completed successfully!"
echo "VM ID: $VMID"
echo "Hostname: $HOSTNAME"
echo "Storage: $STORAGE"
echo "Memory: $MEMORY MB"
echo "Cores: $CORES"
echo "Network Bridge: $BRIDGE"
echo "--------------------------------------------"
echo "You can now start the VM"
