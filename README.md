 <p align="left">
  <a href="https://github.com/vdarkobar/Home-Cloud#self-hosted-cloud">Home</a>
</p>  
  
# Debian Template
## Create Your Own Debian Server Cloud-Init Template

> *Create <a href="https://github.com/vdarkobar/Home-Cloud/blob/main/shared/Proxmox.md#proxmox">Proxmox</a> VM: (1CPU/1GBRAM/16GBHDD) using <a href="https://www.debian.org/">Debian server</a>.  
> *Do not set root password during installation, this way created user will gain sudo privileges.*   
> Add SSH Server during installation.*  
  
### *Run this command and follow the instructions*:
```
clear
sudo apt -y install git && \
RED='\033[0;31m'; NC='\033[0m'; echo -ne "${RED}Enter directory name: ${NC}"; read NAME; mkdir -p "$NAME"; \
cd "$NAME" && git clone https://github.com/vdarkobar/Bastion.git . && \
chmod +x create.sh && \
rm README.md && \
./create.sh
```

<br><br>
<br><br>
*(steps used to configure <a href="https://github.com/vdarkobar/Home-Cloud/blob/main/shared/Bastion.md#bastion">Bastion Server</a>.)*
