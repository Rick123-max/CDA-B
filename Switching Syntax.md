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

- Enable OSPF on a router:
  - Enable OSPF process: `router ospf <process-id>`
  - Assign interfaces to areas: `<network or IP address> <mask> <area-id>`

- `show run interface GigabitEthernet 4` — Displays the interfaces current configuration.configure terminal — Enters the router configuration mode.
- `interface GigabitEthernet 4` — Enters the interface configuration mode.
- `no shutdown` — Enables an interface or process.end —Returns the prompt to enable mode.
- `show ip interface brief GigabitEthernet 4` — Provides a brief summary of the interface and its status.
- `show run | section router ospf 1` — Shows the current configuration section for OSPF process 1.
- `configure terminal` - Enters the routers configuration mode.
- `router ospf 1` — Enter router OSPF process configuration.
- `network 64.210.18.73 0.0.0.0 area 8` — Assign network segment with IP address to the area.
- `no passive-interface GigabitEthernet 4` — For security reasons the command passive-interface default was applied to the router's OSPF process. This disabled all interfaces on the router from forming OSPF adjacency. To enable an interface to form adjacency, the no passive-interface <interface> is required.
- `end` — Returns the prompt to enable mod

- `show .... | include <pattern>` — Parse the output through include and display anything that matches <pattern>.
- `show .... | exclude <pattern>` — Parse the output through exclude and display all output but <pattern>.
- `show .... | section <pattern>` — Parse the output through section and display only the section of the output that matches the <pattern>.

- `show ip ospf neighbor` — Provides a brief summary of the router's current OSPF neighbor.
- `show ip route ospf` — Displays OSPF routes in the routing table.

- Enable password authentication:
  - `ip ospf authentication-key <password>` — Interface-specific command
  - `area area-id authentication` — OSPF process command.

- `ip ospf message-digest-key <keyid> md5 <key>` — Interface-specific command.
- `area area-id authentication message-digest` — OSPF process command.

- Force ASBR go generate a default route: `default-information originate`

- `sh ip bgp "network id"` - Shows info regarding bgp routing
- list all bgp neighbors - `sh ip bgp all`
- display local asn and BGP Neighbors, along with Up/Down times (Established connection) - `sh ip bgp summary`
- `sh ip ospf neighbor` - shows ospf neighbors
- `sh ip route ospf`
