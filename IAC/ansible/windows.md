# Ansible Windows
## Require
 - Package debian: krb5-user
 - Package pip: pywinrm

krb5.conf
```
[libdefaults]
        default_realm = DOMAIN
        dns_lookup_realm = false
        dns_lookup_kdc = false
        ticket_lifetime = 24h
        renew_lifetime = 7d
        forwardable = true
        rdns = false

[realms]
INTRA.DOMAD = {
  kdc = 192.168.0.1
  admin_server   = 192.168.0.1
 }

[domain_realm]
        .domain = DOMAIN
        domain = DOMAIN
```

## Host file
hosts
```
[windows]
assets
[windows:vars]
#ansible_shell_type=powershell
ansible_user=USER@DOMAIN
ansible_connection=winrm
#ansible_winrm_server_cert_validation=ignore
#ansible_port=5986
```

## Run ansible
 - First run "kinit USER"
 - Second run "ansible-playbook -i hosts tasks.yml"

## Tasks
### Remove software
```
---
- hosts: all
  connection: local
  gather_facts: no
  become: true
  become_method: runas
  become_user: USER
  vars:
    product_name: nsclient

  tasks:
  - name: Get Guid of software product name
    ansible.windows.win_shell: Get-WmiObject -Class win32_product| Where-Object {$_.name  -Like "*{{ product_name }}*"}|select IdentifyingNumber
    register: cmdout
  - name: Set guid
    set_fact:
      guid: "{{ cmdout.stdout | regex_search('\\{[0-9A-Z\\-]{36}\\}') }}"
  - name: GUID not found
    fail: msg="GUID of {{ product_name }} not found"
    when: not guid
#  - name : display guid
#    ansible.builtin.debug:
#      msg: "{{ guid }}"
  - name: Uninstall {{ product_name }}
    ansible.windows.win_package:
      product_id: "{{ guid }}"
      state: absent
```

### Integrate/Onboard defender
 - Require: download onboard script on security.microsoft.com -> parameters -> endpoint -> onboard
```
---
- hosts: all
  connection: local
  gather_facts: no
  become: true
  become_method: runas
  become_user: USER
  vars:
    path_upload: C:\temp

  tasks:
    - name: Get Windows version
    block:
      - name: Get Windows version
        win_shell: "systeminfo /fo csv | ConvertFrom-Csv | select OS*, System*, Hotfix* | Format-List"
        register: windows_version
     - name: Set os name
       set_fact:
         os_name: "{{ windows_version | regex_search('OS Name[\t ]*:[a-zA-Z0-9_\\-\t ]+') }}"
     - name: Print Windows host information
       debug:
         msg: "{{ os_name }}"
  - name: Get info for windows defender feature
    community.windows.win_feature_info:
      name: Windows-Defender
    register: feature_info
  - name: feature defender not found
    fail: msg="Feature {{ item.name }} not found {{ item.install_state }}"
    when: not item.installed and (os_name is search("2016") or os_name is search("2019") or os_name is search("2022"))
    loop: "{{ feature_info.features }}"
#TODO check for 2012 if agent is installed
#TODO check for 2008R2 if agent AMA is installed
  - name: onboard windows defender online
  block:
    - name: Check if directory {{ path_upload }} exists
      ansible.windows.win_stat:
        path: "{{ path_upload }}"
      register: dir_data
    - name: Change path upload
      set_fact:
        path_upload: "c:"
      when: not dir_data.stat.exists
    - name: Copy defender script integrate file
      ansible.windows.win_copy:
        src: /tmp/defender.cmd
        dest: "{{ path_upload }}\\defender.cmd"
    - name: Run defender.cmd
      ansible.windows.win_command: "{{ path_upload }}\\defender.cmd"
      register: defender_out
    - name: Remove a file defender.cmd, if present
      ansible.windows.win_file:
        path: C:\Temp\defender.cmd
        state: absent
    - name : display defender
      ansible.builtin.debug:
        msg: "{{ defender_out.stdout }}"
```

### Verify Wsus value
```
---
- hosts: all
  connection: local
  gather_facts: no
  vars:
    wsus_servers: ["https://wsus.local", "https://wsus2.local"]

  tasks:
  - name: Check WSUS registry
    win_reg_stat:
      path: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
      name: "{{ item }}"
    register: reg_val
    loop:
      - WUServer
      - WUStatusServer
  - name: Wsus not valid
    fail: msg="Wsus {{ item.value }} not found in {{ wsus_servers }}"
    when: not item.value or item.value not in wsus_servers
    loop: "{{ reg_val.results }}"
#  - name: Value WSUS
#    debug:
#      msg: "{{ item }}"
#    loop: "{{ reg_val.results }}"
```



