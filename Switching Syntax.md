- Begin a monitoring session to capture trunk ports, and send traffic to another port:
  ```
  S1#configure terminal
  S1(config)#monitor session 1 source interface GigabitEthernet0/0 - 1
  S1(config)#monitor session 1 destination interface GigabitEthernet3/3
  ```
- Check the configuration: `do show running-config | section monitor`
- 
