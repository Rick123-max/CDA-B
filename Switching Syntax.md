- Begin a monitoring session to capture trunk ports, and send traffic to another port:
  ```
  S1#configure terminal
  S1(config)#monitor session 1 source interface GigabitEthernet0/0 - 1
  S1(config)#monitor session 1 destination interface GigabitEthernet3/3
  ```
- Check the configuration: `do show running-config | section monitor`
- Print CAM table: `do show mac address-table`
- Show arp table: `show ip arp`
- Send to a new VLAN and manually configure access ports: `switchport access VLAN <vlan-id>`
- Define native VLAN: `switchport trunk native VLAN <vlan-id>`
- Define VLANs to traverse links: `switchport trunk allowed VLAN <vlan-ids>
- Assign IP addresses on Layer 3 swtich: `<ip-address> <subnet-mask>`
- Set up an SVI by configuring VLAN on switch: `VLAN <vlan-id>`
- Setting up a config example:

   ```
  S1#configure terminal
  Enter configuration commands, one per line. End with CNTL/Z.
  S1(config)#interface Vlan 40
  S1(config-if)#ip address 172.16.22.1 255.255.255.0
  S1(config-if)#no shutdown
  S1(config-if)#interface vlan 45
  S1(config-if)#ip address 192.168.99.1 255.255.255.0
  S1(config-if)#no shutdown
  ```
   
- Add the additional `no switchport` command:

  ```
  S1#configure terminal
  Enter configuration commands, one per line. End with CNTL/Z.
  S11(config)#int gi1/0/14
  S1(config-if)#no switchport
  S1(config-if)#ip address 10.20.20.1 255.255.255.0
  S1(config-if)#ipv6 address 2001:db8:20::1/64
  S1(config-if)#no shutdown
  S1(config-if)#end
  S1
  ```

- Show the spanning tree information: `show spanning-tree root`
- 
