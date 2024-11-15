#!/bin/bash

# Exit on any error
set -e

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
IMAGE_PATH="/srv/$IMAGE_NAME"

# Prompt for custom image URL or use default
read -p "Enter custom image URL or press Enter to use default [$DEFAULT_IMAGE_URL]: " IMAGE_URL
IMAGE_URL="${IMAGE_URL:-$DEFAULT_IMAGE_URL}"

# Check if Debian image file already exists in /srv
USE_EXISTING=false
if [[ -f "$IMAGE_PATH" ]]; then
    read -p "Debian image already exists in /srv. Use it? (y/n): " USE_EXISTING_RESPONSE
    if [[ "$USE_EXISTING_RESPONSE" =~ ^[Yy]$ ]]; then
        USE_EXISTING=true
    else
        wget --timeout=300 --tries=3 -q --show-progress -O "$IMAGE_PATH" "$IMAGE_URL"
    fi
else
    wget --timeout=300 --tries=3 -q --show-progress -O "$IMAGE_PATH" "$IMAGE_URL"
fi

# Only download and verify checksum if not using an existing image
if ! $USE_EXISTING; then
    TEMP_DIR=$(mktemp -d)
    CHECKSUMS_URL="${IMAGE_URL%/*}/SHA512SUMS"
    wget -q -O "$TEMP_DIR/SHA512SUMS" "$CHECKSUMS_URL"
    (cd "/srv" && grep "$IMAGE_NAME" "$TEMP_DIR/SHA512SUMS" | sha512sum -c --status)
    rm -rf "$TEMP_DIR"
fi

# Prompt for username with validation
while true; do
    read -p "Enter the username for the new user: " username
    if [[ "$username" =~ ^[a-z_][a-z0-9_-]{2,15}$ ]]; then
        break
    else
        echo "Invalid username."
    fi
done

# If using an existing image, check if the user already exists
if $USE_EXISTING; then
    if virt-customize -a "$IMAGE_PATH" --run-command "id -u $username" >/dev/null 2>&1; then
        echo "[INFO] User '$username' already exists on the image."
        USER_EXISTS=true
    else
        USER_EXISTS=false
    fi
else
    USER_EXISTS=false
fi

# Prompt for password only if user does not exist
if ! $USER_EXISTS; then
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
fi

# Script functionality starts here

# List .qcow2 files in /srv folder and select
qcow2_files=($(ls /srv/*.qcow2 2>/dev/null))
if [ ${#qcow2_files[@]} -eq 0 ]; then
    echo "No .qcow2 files found in /srv."
    exit 1
elif [ ${#qcow2_files[@]} -gt 1 ]; then
    select file_to_use in "${qcow2_files[@]}"; do
        if [[ -n "$file_to_use" ]]; then
            image_path="$file_to_use"
            break
        else
            echo "Invalid selection."
        fi
    done
else
    image_path="${qcow2_files[0]}"
fi

# Run virt-customize commands
if ! $USER_EXISTS; then
    virt-customize -a "$image_path" \
        --install qemu-guest-agent,sudo,openssh-server \
        --run-command "useradd -m -s /bin/bash $username" \
        --password "$username:password:$user_password" \
        --run-command "usermod -aG sudo $username" \
        --run-command "passwd -l root" \
        --run-command "echo -n > /etc/machine-id"
else
    virt-customize -a "$image_path" \
        --install qemu-guest-agent,sudo,openssh-server \
        --run-command "echo -n > /etc/machine-id"
fi

# Verify storage space
image_size=$(stat -f --format="%s" "$IMAGE_PATH")
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

# Import Debian disk image and set as primary boot disk
qm importdisk "$VMID" "$IMAGE_PATH" "$STORAGE"
qm set "$VMID" --scsi0 "$STORAGE:vm-$VMID-disk-0,discard=on,ssd=1,cache=none" --boot order=scsi0 --ostype l26

echo "[INFO] VM creation completed successfully!"
echo "VM ID: $VMID"
echo "Hostname: $HOSTNAME"
echo "Storage: $STORAGE"
echo "Memory: $MEMORY MB"
echo "Cores: $CORES"
echo "Network Bridge: $BRIDGE"
echo "----------------------------------------"
echo "You can now start the VM using: qm start $VMID"
