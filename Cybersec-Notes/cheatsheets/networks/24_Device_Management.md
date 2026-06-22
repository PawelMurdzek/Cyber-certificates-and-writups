# Device Management

## IOS File Management

### File System Locations

| Location | Description |
|----------|-------------|
| **flash:** | Primary IOS storage |
| **nvram:** | Startup configuration |
| **running-config** | Active config (RAM) |
| **startup-config** | Saved config (NVRAM) |

### File Commands
```cisco
! List files
dir flash:
show flash:

! View file
more flash:config.txt

! Copy files
copy running-config startup-config
copy startup-config tftp:
copy tftp: flash:

! Delete files
delete flash:old-ios.bin

! Rename files
rename flash:old.txt flash:new.txt
```

---

## Configuration Management

### Save Configuration
```cisco
copy running-config startup-config
! Or shorthand
write memory
wr
```

### Backup Configuration
```cisco
! To TFTP server
copy running-config tftp:
! Enter TFTP server IP and filename

! To USB
copy running-config usbflash0:backup.cfg

! To terminal (display)
show running-config
```

### Restore Configuration
```cisco
! From TFTP
copy tftp: running-config

! From startup
copy startup-config running-config

! Merge vs Replace
configure replace flash:backup.cfg
```

### Erase Configuration
```cisco
write erase
! Or
erase startup-config

! Then reload
reload
```

---

## IOS Image Management

### Verify Current IOS
```cisco
show version
show flash:
```

### Backup IOS
```cisco
copy flash:c2900-universalk9-mz.SPA.bin tftp:
```

### Upgrade IOS via TFTP
```cisco
! Copy new image
copy tftp: flash:
! Enter TFTP server and filename

! Set boot image
boot system flash:new-ios-image.bin

! Save and reload
write memory
reload
```

### Upgrade via USB
```cisco
copy usbflash0:new-ios.bin flash:
boot system flash:new-ios.bin
write memory
reload
```

---

## Password Recovery

### Router Password Recovery

1. Power off router
2. Reconnect power, press **Break** during boot
3. Enter ROMMON mode
4. Change config register to skip startup-config:
   ```
   rommon 1 > confreg 0x2142
   rommon 2 > reset
   ```
5. Router boots without config
6. Enter privileged mode, copy startup to running:
   ```cisco
   enable
   copy startup-config running-config
   ```
7. Change passwords:
   ```cisco
   enable secret NewPassword
   ```
8. Reset config register:
   ```cisco
   config-register 0x2102
   ```
9. Save and reload:
   ```cisco
   write memory
   reload
   ```

### Switch Password Recovery

1. Power off switch
2. Hold **Mode** button, power on
3. Release when lights change
4. Initialize flash:
   ```
   switch: flash_init
   switch: load_helper
   ```
5. Rename config:
   ```
   switch: rename flash:config.text flash:config.old
   ```
6. Boot normally:
   ```
   switch: boot
   ```
7. After boot, rename config back:
   ```cisco
   rename flash:config.old flash:config.text
   copy flash:config.text running-config
   ```
8. Change passwords and save

---

## Licensing

### Traditional Licensing (Pre-15.0)
```cisco
show license
license install flash:license.lic
```

### Smart Licensing
```cisco
! Configure Smart License
license smart enable
license smart register idtoken [token]

! Verify
show license status
show license summary
show license usage
```

### Right-to-Use (RTU) Licensing
```cisco
! Accept license agreement
license accept end user agreement
license boot module [module] technology-package [package]
write memory
reload
```

---

## Device Monitoring

### CPU and Memory
```cisco
show processes cpu
show processes cpu history
show memory
show memory summary
```

### Interface Statistics
```cisco
show interfaces
show interfaces status
show interfaces counters
show interfaces counters errors
```

### System Information
```cisco
show version                  ! IOS version, uptime, memory
show inventory               ! Hardware components
show environment             ! Temperature, power
show platform                ! Platform-specific
```

---

## Backup and Restore Best Practices

### Configuration Archive
```cisco
archive
  path flash:config-archive
  write-memory
  maximum 14
  time-period 1440           ! Auto-backup every 24 hours
```

### View Archives
```cisco
show archive
! Rollback
configure replace flash:config-archive-1
```

---

## TFTP/FTP/SCP Setup

### TFTP
```cisco
copy running-config tftp://192.168.1.100/backup.cfg
copy tftp://192.168.1.100/new-ios.bin flash:
```

### FTP
```cisco
ip ftp username admin
ip ftp password MyPassword
copy running-config ftp://192.168.1.100/backup.cfg
```

### SCP (Secure)
```cisco
ip scp server enable
copy running-config scp://admin@192.168.1.100/backup.cfg
```

---

## Boot Process

### Boot Sequence
1. **POST**: Power-On Self-Test
2. **Bootstrap**: Load and run bootstrap
3. **Find IOS**: Check boot system commands
4. **Load IOS**: From flash (default)
5. **Load Config**: startup-config to running-config

### Boot System Commands
```cisco
boot system flash:preferred-ios.bin
boot system tftp://192.168.1.100/backup-ios.bin
boot system rom                    ! Fallback

! Verify
show boot
```

---

## Configuration Register

| Value | Meaning |
|-------|---------|
| 0x2102 | Normal boot |
| 0x2142 | Ignore startup-config |
| 0x2101 | Boot from ROM |
| 0x2100 | Boot to ROMMON |

```cisco
config-register 0x2102
show version | include register
```

---

## NTP Configuration

```cisco
ntp server 0.pool.ntp.org prefer
ntp server 1.pool.ntp.org

clock timezone EST -5
clock summer-time EDT recurring

show ntp status
show ntp associations
show clock
```

---

## Scheduled Reloads

```cisco
! Reload in 5 minutes
reload in 5

! Reload at specific time
reload at 22:00

! Cancel reload
reload cancel

! Show pending reload
show reload
```

---

## Troubleshooting Commands

```cisco
! General debug (use carefully!)
debug all                        ! WARNING: High CPU
undebug all

! Interface debug
debug ip packet

! System logging
show logging
logging console debugging
logging buffered 16384

! Show tech-support
show tech-support
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Save config | `copy run start` or `wr` |
| Backup to TFTP | `copy run tftp:` |
| Show version | `show version` |
| Show flash | `dir flash:` |
| Password recovery | Change confreg to 0x2142 |
| Erase config | `write erase` |
| Reload | `reload` |
| Schedule reload | `reload in [minutes]` |
| Cancel reload | `reload cancel` |
| Show boot | `show boot` |
