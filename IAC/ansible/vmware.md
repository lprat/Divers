# Vmware ansible
## Check Rights on VM & DataStore
````
---
- hosts: all
  connection: local
  gather_facts: no
  vars_prompt:
    - name: "vcenter_password"
      prompt: "vSphere Password"
  vars:
    vcenter_hostname: host_vcenter_change_it
    vcenter_username: user_vcenter_change_it

  tasks:
  - name: Gather information about all datacenters
    community.vmware.vmware_datacenter_info:
      hostname: '{{ vcenter_hostname }}'
      username: '{{ vcenter_username }}'
      password: '{{ vcenter_password }}'
      validate_certs: false
    delegate_to: localhost
    register: vm_datacenters
  - name: Datacenters Info
    debug:
      msg: "{{ vm_datacenters }}"
  - name: Gather role information about Datastore
    community.vmware.vmware_object_role_permission_info:
      hostname: "{{ vcenter_hostname }}"
      username: "{{ vcenter_username }}"
      password: "{{ vcenter_password }}"
      validate_certs: false
      object_name: "{{ item.name}}"
      object_type: Datacenter
    register: dc_right
    loop: "{{ vm_datacenters.datacenter_info }}"
  - name: Datacenter Right Info
    debug:
      msg: "{{ dc_right }}"
  - name: Gather cluster info from given datacenter
    community.vmware.vmware_cluster_info:
      hostname: '{{ vcenter_hostname }}'
      username: '{{ vcenter_username }}'
      password: '{{ vcenter_password }}'
      datacenter: "{{ item.name}}"
      validate_certs: false
    delegate_to: localhost
    register: cluster_info
    loop: "{{ vm_datacenters.datacenter_info }}"
  - name: Cluster Info
    debug:
      msg: "{{ cluster_info }}"
# Require https://sky-jokerxx.medium.com/how-to-use-vsan-modules-for-community-vmware-with-ansible-664702e097c4
#  - name: Gather health info from a vSAN's cluster
#    community.vmware.vmware_vsan_health_info:
#      hostname: "{{ vcenter_hostname }}"
#      username: "{{ vcenter_username }}"
#      password: "{{ vcenter_password }}"
#      validate_certs: false
#      cluster_name: "{{ item.key }}"
#      fetch_from_cache: false
#    register: vsan_info
#    with_dict: "{{ cluster_info.results.0.clusters }}"
#  - name: VSAN Info
#    debug:
#      msg: "{{ vsan_info }}"
  - name: Gather info from standalone ESXi server having datacenter
    community.vmware.vmware_datastore_info:
      hostname: '{{ vcenter_hostname }}'
      username: '{{ vcenter_username }}'
      password: '{{ vcenter_password }}'
      validate_certs: false
      datacenter_name: "{{ item.name }}"
    delegate_to: localhost
    register: vm_datastore
    loop: "{{ vm_datacenters.datacenter_info }}"
  - name: Datastore Info
    debug:
      msg: "{{ vm_datastore }}"
  - name: Gather role information about Datastore
    community.vmware.vmware_object_role_permission_info:
      hostname: "{{ vcenter_hostname }}"
      username: "{{ vcenter_username }}"
      password: "{{ vcenter_password }}"
      validate_certs: false
      object_name: "{{ item.name}}"
      object_type: Datastore
    register: ds_right
    loop: "{{ vm_datastore.results.0.datastores }}"
    #TODO: change to double loop if >1 results
  - name: Datastore Right Info
    debug:
      msg: "{{ ds_right }}"
#https://docs.ansible.com/ansible/latest/collections/community/vmware/vmware_object_role_permission_info_module.html
  - name: Gather all registered virtual machines
    community.vmware.vmware_vm_info:
      hostname: '{{ vcenter_hostname }}'
      username: '{{ vcenter_username }}'
      password: '{{ vcenter_password }}'
      validate_certs: false
    delegate_to: localhost
    register: vm_vminfo
  - name: Gather role information about VM
    community.vmware.vmware_object_role_permission_info:
      hostname: "{{ vcenter_hostname }}"
      username: "{{ vcenter_username }}"
      password: "{{ vcenter_password }}"
      validate_certs: false
      object_name: "{{ item.guest_name}}"
      object_type: VirtualMachine
    register: vm_right
    loop: "{{ vm_vminfo.virtual_machines }}"
  - name: VM Info
    debug:
      msg: "{{ vm_right }}"
