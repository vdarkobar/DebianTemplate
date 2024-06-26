 <p align="left">
  <a href="https://github.com/vdarkobar/Home-Cloud/tree/main?tab=readme-ov-file#create-debian-server-template">Home</a>
</p>  
  
# Debian Template
## Create Your Own Debian Server Cloud-Init Template to use with Proxmox

> *Create <a href="https://github.com/vdarkobar/Home-Cloud/blob/main/shared/Proxmox.md#proxmox">Proxmox</a> VM: (2CPU/2GBRAM/16GBHDD) using <a href="https://www.debian.org/">Debian</a>.*  
> *Do not set root password during installation, this way created user will gain sudo privileges.*   
> *Add SSH Server during installation.*  
> *For ProxMox VM disk Resize option to work, create VM without SWAP Partition during install process*
```bash
Partition disks > Manual > Continue
Select disk > SCSI3 QEMU HARDDISK > Continue
Create new empty Partition > Yes > Continue
New Partition Size > Continue
Primary > Continue
Bootable Flag > On > Done setting up the Partition > Continue
Finish partitioning and write changes to the disk > Continue
Return to the partitioning menu > No > Continue
Write changes to the disk > Yes > Continue
```
> *(VM > Hardware > Hard Disk > Disk Action > Resize)*  
  
### *Run this command and follow the instructions*:

```
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/DebianTemplate/main/test.sh)"
```


<br><br>
*(steps used to configure <a href="https://github.com/vdarkobar/Home-Cloud/blob/main/shared/Debian.md#debian">Debian Server Template</a>)*
