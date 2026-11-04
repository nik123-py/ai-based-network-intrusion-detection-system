# Cisco Packet Tracer topology guide

Packet Tracer saves networks in a proprietary binary `.pkt` format that cannot be generated from code, so this file is a build guide. It produces a scalable enterprise topology that shows where Netra sensors sit in a real network: a redundant internet edge, a firewall with a DMZ, a redundant collapsed-core campus with VLANs, a server farm, a WAN that any number of branches can join, and Netra sensors at the two main choke points reporting to a central console.

Packet Tracer models the topology, addressing, routing and traffic paths. The real detection and response run in the Docker lab (see `DEMO_GUIDE.md`), which corresponds to one sensor protecting the DMZ web server.

Tested layout: Packet Tracer 8.2. Device models are suggestions; similar models work if the interface names are adjusted.

## Contents

1. Design goals
2. Topology
3. Addressing and VLAN plan
4. Device inventory and cabling
5. Build steps
6. Demonstrating detection and response
7. Scaling the design
8. Mapping to the Netra Docker lab
9. Packet Tracer limitations

## 1. Design goals

| Goal | How the design meets it |
|---|---|
| Scalable addressing | Hierarchical plan: one /16 per site, third octet equals the VLAN ID, so every subnet is derivable from its VLAN and site. Each site summarises to a single route. |
| Scalable switching | Collapsed core (two multilayer switches) with identical access blocks. A new access switch is a copy of an existing one plus two uplinks. |
| Redundancy | Two edge routers with HSRP, two core switches with HSRP and an EtherChannel between them, dual-homed access switches, Rapid PVST+ with load-shared roots. |
| Scalable routing | OSPF inside the enterprise. The cores originate the default route, so branches learn internet access automatically. The WAN is a shared segment, so a new branch needs no new interface at headquarters. |
| Scalable monitoring | One Netra sensor per choke point (DMZ and campus core), each with a passive capture port fed by SPAN and a separate management port. All sensors report to one console in the server farm. |
| Manageability | Out-of-band management VLAN, SSH only, central DHCP, DNS, NTP and syslog, one baseline configuration on every device. |

## 2. Topology

```
                       INTERNET ZONE (simulated)
        [EXT-CLIENT 203.0.113.130]   [ATTACKER 203.0.113.200]
                       \                 /
                        [SW-INET 2960]
                              |
                        [ISP  ISR4331]
                        /            \
             203.0.113.0/30      203.0.113.4/30
                      /              \
          [R-EDGE1 ISR4331]    [R-EDGE2 ISR4331]    HSRP VIP 198.51.100.1
                      \              /
                       [SW-OUT 2960] 198.51.100.0/29
                              |
                        outside .6
                     [FW  ASA 5506-X]
                 dmz 172.16.10.1  inside 10.10.100.6
                   |                   |
     DMZ 172.16.10.0/24                | VLAN 100 transit 10.10.100.0/29
        [SW-DMZ 2960]                  |
        |         |                    |
     [WEB]   [NIDS-DMZ]     +----------+---------------------------+
     .10      SPAN dest     | [CORE1 3560] ==Po1== [CORE2 3560]    | HSRP .1 per VLAN
                            |    |  \ SPAN         /   |            | OSPF area 0
                            |    |  [NIDS-CORE]   /    |            |
                            |  [ACC1]        [ACC2]  [SW-SRV]       |
                            |  staff/eng/mgmt        server farm    |
                            +--------------------------------------+
                                  |                  |
                            10.255.0.0/30     10.255.0.4/30
                                   \              /
                                  [R-WAN ISR4331]
                                         |
                             WAN segment 10.255.1.0/24
                                  [SW-WAN 2960]
                                  /     |     \
                            [R-BR1] (R-BR2) (R-BRn)   branches join here
                               |
                          [BR-SW1 2960]
                          BR-PC1  BR-PC2
```

Traffic each sensor sees:

| Sensor | Capture source (SPAN) | Traffic observed |
|---|---|---|
| NIDS-DMZ | SW-DMZ Fa0/1 (WEB) and Gi0/1 (firewall DMZ link) | Everything to and from the public web server (north-south) |
| NIDS-CORE | CORE1 Fa0/20 (firewall inside link) | Campus, branch and inside-to-DMZ traffic (east-west and user internet) |

## 3. Addressing and VLAN plan

### 3.1 Address blocks

| Block | Use | Rule |
|---|---|---|
| 10.10.0.0/16 | Headquarters campus | 10.10.**V**.0/24 where **V** is the VLAN ID |
| 10.21.0.0/16 to 10.99.0.0/16 | Branch sites | Branch **n** uses 10.(20+**n**).0.0/16, same VLAN rule |
| 10.254.0.0/24 | Router loopbacks (OSPF router IDs) | one /32 per routing device |
| 10.255.0.0/24 | Campus point-to-point links | /30 per link |
| 10.255.1.0/24 | Shared WAN segment | R-WAN .1, branch **n** router .(20+**n**) |
| 172.16.10.0/24 | DMZ | public-facing servers |
| 198.51.100.0/29 | Outside segment (edge routers and firewall) | documentation range |
| 203.0.113.0/24 | Simulated internet and ISP links | documentation range |

Every site summarises to one route (for example 10.21.0.0/16 for branch 1), so the routing table stays small as sites are added.

### 3.2 VLANs (same IDs at every site)

| VLAN | Name | HQ subnet | Branch 1 subnet | Gateway |
|---|---|---|---|---|
| 10 | MGMT | 10.10.10.0/24 | 10.21.10.0/24 | .1 |
| 20 | STAFF | 10.10.20.0/24 | 10.21.20.0/24 | .1 |
| 30 | ENG | 10.10.30.0/24 | not used | .1 |
| 50 | SERVERS | 10.10.50.0/24 | not used | .1 |
| 99 | NATIVE | trunk native VLAN, carries no user traffic | | none |
| 100 | FW-TRANSIT | 10.10.100.0/29 | not used | .1 (HSRP) |
| 999 | PARKING | unused ports, shut down | | none |

At headquarters the gateway .1 is an HSRP virtual address. CORE1 owns .2 and CORE2 owns .3 in every VLAN.

### 3.3 Device addresses

| Device | Interface | Address | Gateway / next hop |
|---|---|---|---|
| ISP | G0/0/0 | 203.0.113.1/30 | none |
| ISP | G0/0/1 | 203.0.113.5/30 | none |
| ISP | G0/0/2 | 203.0.113.129/25 | none |
| EXT-CLIENT | Fa0 | 203.0.113.130/25 | 203.0.113.129 |
| ATTACKER | Fa0 | 203.0.113.200/25 | 203.0.113.129 |
| R-EDGE1 | G0/0/0 | 203.0.113.2/30 | default to 203.0.113.1 |
| R-EDGE1 | G0/0/1 | 198.51.100.2/29 (HSRP VIP .1, active) | none |
| R-EDGE2 | G0/0/0 | 203.0.113.6/30 | default to 203.0.113.5 |
| R-EDGE2 | G0/0/1 | 198.51.100.3/29 (HSRP VIP .1, standby) | none |
| FW | G1/1 outside | 198.51.100.6/29 | default to 198.51.100.1 |
| FW | G1/2 inside | 10.10.100.6/29 | 10.0.0.0/8 via 10.10.100.1 |
| FW | G1/3 dmz | 172.16.10.1/24 | none |
| WEB | Fa0 | 172.16.10.10/24 | 172.16.10.1 |
| NIDS-DMZ | Fa0 (capture) | no address | none |
| NIDS-DMZ | Fa1 (management) | 10.10.10.51/24 | 10.10.10.1 |
| CORE1 | SVI VLAN 10/20/30/50/100 | .2 in each subnet | default to 10.10.100.6 |
| CORE1 | G0/1 (routed) | 10.255.0.2/30 | none |
| CORE1 | Loopback0 | 10.254.0.1/32 | none |
| CORE2 | SVI VLAN 10/20/30/50/100 | .3 in each subnet | default to 10.10.100.6 |
| CORE2 | G0/1 (routed) | 10.255.0.6/30 | none |
| CORE2 | Loopback0 | 10.254.0.2/32 | none |
| NIDS-CORE | Fa0 (capture) | no address | none |
| NIDS-CORE | Fa1 (management) | 10.10.10.52/24 | 10.10.10.1 |
| ADMIN-PC | Fa0 | 10.10.10.100/24 | 10.10.10.1 |
| PC-STAFF1, PC-STAFF2 | Fa0 | DHCP (10.10.20.100+) | 10.10.20.1 |
| PC-ENG1, PC-ENG2 | Fa0 | DHCP (10.10.30.100+) | 10.10.30.1 |
| SRV-CORE (DHCP/DNS/NTP) | Fa0 | 10.10.50.10/24 | 10.10.50.1 |
| SRV-LOG (syslog) | Fa0 | 10.10.50.20/24 | 10.10.50.1 |
| NETRA-CONSOLE | Fa0 | 10.10.50.30/24 | 10.10.50.1 |
| R-WAN | G0/0/0 | 10.255.0.1/30 | none |
| R-WAN | G0/0/1 | 10.255.0.5/30 | none |
| R-WAN | G0/0/2 | 10.255.1.1/24 | none |
| R-WAN | Loopback0 | 10.254.0.3/32 | none |
| R-BR1 | G0/0/0 | 10.255.1.21/24 | none |
| R-BR1 | G0/0/1.10 / .20 | 10.21.10.1/24, 10.21.20.1/24 | none |
| R-BR1 | Loopback0 | 10.254.0.21/32 | none |
| BR-PC1, BR-PC2 | Fa0 | DHCP (10.21.20.100+) | 10.21.20.1 |

The design routes private addresses end to end with no NAT, so paths are easy to follow in simulation mode. A production network would add PAT for inside users and static NAT for the web server on the firewall; see section 7.

## 4. Device inventory and cabling

### 4.1 Devices (31 total)

| Zone | Device | Packet Tracer model | Count |
|---|---|---|---|
| Internet | ISP | ISR4331 | 1 |
| Internet | SW-INET | 2960-24TT | 1 |
| Internet | EXT-CLIENT, ATTACKER | PC-PT | 2 |
| Edge | R-EDGE1, R-EDGE2 | ISR4331 | 2 |
| Edge | SW-OUT | 2960-24TT | 1 |
| Security | FW | ASA 5506-X | 1 |
| DMZ | SW-DMZ | 2960-24TT | 1 |
| DMZ | WEB | Server-PT | 1 |
| DMZ | NIDS-DMZ | Server-PT + second NIC | 1 |
| Core | CORE1, CORE2 | 3560-24PS | 2 |
| Core | NIDS-CORE | Server-PT + second NIC | 1 |
| Access | ACC1, ACC2 | 2960-24TT | 2 |
| Access | PC-STAFF1/2, PC-ENG1/2, ADMIN-PC | PC-PT | 5 |
| Server farm | SW-SRV | 2960-24TT | 1 |
| Server farm | SRV-CORE, SRV-LOG, NETRA-CONSOLE | Server-PT | 3 |
| WAN | R-WAN | ISR4331 | 1 |
| WAN | SW-WAN | 2960-24TT | 1 |
| Branch 1 | R-BR1 | ISR4331 | 1 |
| Branch 1 | BR-SW1 | 2960-24TT | 1 |
| Branch 1 | BR-PC1, BR-PC2 | PC-PT | 2 |

The 3560-24PS is used for the cores because it has built-in power; the 3650 needs a power module added before it boots.

### 4.2 Adding the second NIC to each sensor

A sensor needs one port for capture (no IP address) and one for management.

1. Click **NIDS-DMZ**, open the **Physical** tab and press the power button to turn it off.
2. Drag the module **PT-HOST-NM-1CFE** into the empty slot.
3. Turn the power back on. The new port appears as **FastEthernet1**.
4. Repeat for **NIDS-CORE**.

### 4.3 Access-switch port plan (same on every access switch)

| Ports | Role | VLAN |
|---|---|---|
| Fa0/1 to Fa0/4 | staff users | 20 |
| Fa0/5 to Fa0/8 | engineering users | 30 |
| Fa0/9 to Fa0/10 | management (admin PC, sensor mgmt ports) | 10 |
| Fa0/11 to Fa0/24 | unused, shut down | 999 |
| Gi0/1 | uplink to CORE1 | trunk |
| Gi0/2 | uplink to CORE2 | trunk |

On SW-SRV, Fa0/1 to Fa0/8 are in VLAN 50 instead of 20 and 30.

### 4.4 Core-switch port plan

| Ports | Role |
|---|---|
| Fa0/1 to Fa0/12 | access-switch uplinks (Fa0/1 ACC1, Fa0/2 ACC2, Fa0/3 SW-SRV, Fa0/4+ new switches) |
| Fa0/20 | CORE1 only: firewall inside link (VLAN 100), SPAN source |
| Fa0/21 | CORE1 only: NIDS-CORE capture port (SPAN destination) |
| Fa0/23 to Fa0/24 | EtherChannel Po1 to the other core |
| Gi0/1 | routed link to R-WAN |

### 4.5 Cabling

Use **Copper Cross-Over** between two switches and between two routers. Use **Copper Straight-Through** for everything else.

| # | From | Port | To | Port | Cable |
|---|---|---|---|---|---|
| 1 | EXT-CLIENT | Fa0 | SW-INET | Fa0/1 | straight |
| 2 | ATTACKER | Fa0 | SW-INET | Fa0/2 | straight |
| 3 | ISP | G0/0/2 | SW-INET | G0/1 | straight |
| 4 | ISP | G0/0/0 | R-EDGE1 | G0/0/0 | cross-over |
| 5 | ISP | G0/0/1 | R-EDGE2 | G0/0/0 | cross-over |
| 6 | R-EDGE1 | G0/0/1 | SW-OUT | Fa0/1 | straight |
| 7 | R-EDGE2 | G0/0/1 | SW-OUT | Fa0/2 | straight |
| 8 | FW | G1/1 | SW-OUT | Fa0/3 | straight |
| 9 | FW | G1/3 | SW-DMZ | G0/1 | straight |
| 10 | WEB | Fa0 | SW-DMZ | Fa0/1 | straight |
| 11 | NIDS-DMZ | Fa0 | SW-DMZ | Fa0/24 | straight |
| 12 | FW | G1/2 | CORE1 | Fa0/20 | straight |
| 13 | CORE1 | Fa0/23 | CORE2 | Fa0/23 | cross-over |
| 14 | CORE1 | Fa0/24 | CORE2 | Fa0/24 | cross-over |
| 15 | ACC1 | G0/1 | CORE1 | Fa0/1 | cross-over |
| 16 | ACC1 | G0/2 | CORE2 | Fa0/1 | cross-over |
| 17 | ACC2 | G0/1 | CORE1 | Fa0/2 | cross-over |
| 18 | ACC2 | G0/2 | CORE2 | Fa0/2 | cross-over |
| 19 | SW-SRV | G0/1 | CORE1 | Fa0/3 | cross-over |
| 20 | SW-SRV | G0/2 | CORE2 | Fa0/3 | cross-over |
| 21 | NIDS-CORE | Fa0 | CORE1 | Fa0/21 | straight |
| 22 | CORE1 | G0/1 | R-WAN | G0/0/0 | straight |
| 23 | CORE2 | G0/1 | R-WAN | G0/0/1 | straight |
| 24 | R-WAN | G0/0/2 | SW-WAN | G0/1 | straight |
| 25 | R-BR1 | G0/0/0 | SW-WAN | Fa0/1 | straight |
| 26 | R-BR1 | G0/0/1 | BR-SW1 | G0/1 | straight |
| 27 | BR-PC1 | Fa0 | BR-SW1 | Fa0/1 | straight |
| 28 | BR-PC2 | Fa0 | BR-SW1 | Fa0/2 | straight |
| 29 | PC-STAFF1 | Fa0 | ACC1 | Fa0/1 | straight |
| 30 | PC-ENG1 | Fa0 | ACC1 | Fa0/5 | straight |
| 31 | ADMIN-PC | Fa0 | ACC1 | Fa0/9 | straight |
| 32 | NIDS-DMZ | Fa1 | ACC1 | Fa0/10 | straight |
| 33 | PC-STAFF2 | Fa0 | ACC2 | Fa0/1 | straight |
| 34 | PC-ENG2 | Fa0 | ACC2 | Fa0/5 | straight |
| 35 | NIDS-CORE | Fa1 | ACC2 | Fa0/10 | straight |
| 36 | SRV-CORE | Fa0 | SW-SRV | Fa0/1 | straight |
| 37 | SRV-LOG | Fa0 | SW-SRV | Fa0/2 | straight |
| 38 | NETRA-CONSOLE | Fa0 | SW-SRV | Fa0/3 | straight |

Tip: arrange devices in zones top to bottom (internet, edge, firewall, DMZ on the left, campus in the middle, WAN and branch at the bottom) and label each zone with **Place Note**. The diagram is then readable on a slide.

## 5. Build steps

Build in stages and run the check at the end of each stage before moving on. A mistake is far easier to find in a stage of five devices than in a network of thirty.

### Stage 1: place and cable

1. **File > New**.
2. Place the 31 devices from section 4.1 and rename each by clicking its label.
3. Add the second NIC to both sensors (section 4.2).
4. Cable everything from the table in section 4.5.
5. Set the static addresses on the end devices (**Desktop > IP Configuration**): EXT-CLIENT, ATTACKER, WEB, ADMIN-PC, SRV-CORE, SRV-LOG, NETRA-CONSOLE. On the sensors, set the address on **FastEthernet1** only and leave FastEthernet0 unaddressed. Leave the user PCs on DHCP; they get addresses in stage 8.

**Check:** switch ports turn green after about 30 seconds. Router and firewall links stay red until their interfaces are enabled in later stages.

### Stage 2: baseline configuration on every switch and router

Apply this block to every IOS device (all routers and switches, not the ASA, not the end devices), changing `HOSTNAME` each time. The same baseline everywhere is what keeps a large network manageable.

```
enable
configure terminal
hostname HOSTNAME
no ip domain-lookup
ip domain-name netra.lab
service password-encryption
service timestamps log datetime msec
enable secret Netra-Enable-1
username admin privilege 15 secret Netra-Admin-1
banner motd # Authorised access only. Netra lab network. #
crypto key generate rsa general-keys modulus 1024
ip ssh version 2
ip access-list standard MGMT-ONLY
 permit 10.10.10.0 0.0.0.255
line vty 0 15
 transport input ssh
 login local
 access-class MGMT-ONLY in
line console 0
 logging synchronous
 exec-timeout 15 0
ntp server 10.10.50.10
logging host 10.10.50.20
logging trap informational
end
write memory
```

Only hosts in the management VLAN can open SSH sessions, which keeps device management off the user networks. NTP and syslog point at the server farm and begin working once routing is up in stage 4.

**Check:** `show running-config | include hostname|ssh|logging` on a couple of devices.

### Stage 3: VLANs, trunks, EtherChannel and spanning tree

VTP is transparent so each switch keeps its own VLAN list; an accidental VLAN deletion then cannot spread, which matters more as the switch count grows.

**On CORE1 and CORE2** (identical except the root priorities at the end):

```
configure terminal
vtp mode transparent
vlan 10
 name MGMT
vlan 20
 name STAFF
vlan 30
 name ENG
vlan 50
 name SERVERS
vlan 99
 name NATIVE
vlan 100
 name FW-TRANSIT
vlan 999
 name PARKING
spanning-tree mode rapid-pvst
interface range fa0/1 - 12
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 10,20,30,50,99
 switchport nonegotiate
interface range fa0/23 - 24
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 10,20,30,50,99,100
 channel-group 1 mode active
interface port-channel 1
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 10,20,30,50,99,100
end
write memory
```

**CORE1 only**, roots and the firewall port:

```
configure terminal
spanning-tree vlan 10,30,100 root primary
spanning-tree vlan 20,50 root secondary
interface fa0/20
 description FW inside
 switchport mode access
 switchport access vlan 100
 spanning-tree portfast
end
write memory
```

**CORE2 only:**

```
configure terminal
spanning-tree vlan 20,50 root primary
spanning-tree vlan 10,30,100 root secondary
end
write memory
```

CORE1 is root and (from stage 4) active gateway for VLANs 10, 30 and 100; CORE2 for VLANs 20 and 50. Both uplinks of every access switch carry traffic, and either core can take over all VLANs if the other fails.

**On ACC1 and ACC2** (the access template; reused for every future access switch):

```
configure terminal
vtp mode transparent
vlan 10
 name MGMT
vlan 20
 name STAFF
vlan 30
 name ENG
vlan 99
 name NATIVE
vlan 999
 name PARKING
spanning-tree mode rapid-pvst
interface range g0/1 - 2
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 10,20,30,99
 switchport nonegotiate
interface range fa0/1 - 4
 switchport mode access
 switchport access vlan 20
interface range fa0/5 - 8
 switchport mode access
 switchport access vlan 30
interface range fa0/9 - 10
 switchport mode access
 switchport access vlan 10
interface range fa0/1 - 10
 spanning-tree portfast
 spanning-tree bpduguard enable
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation restrict
 switchport port-security mac-address sticky
interface range fa0/11 - 24
 switchport mode access
 switchport access vlan 999
 shutdown
end
write memory
```

**On SW-SRV:** the same template, but put Fa0/1 to Fa0/8 in VLAN 50 and allow VLAN 50 (not 20 and 30) on the uplinks.

**SPAN sessions.** The capture port receives a copy of the monitored traffic and belongs to no VLAN.

SW-DMZ (mirror the web server and the firewall link to the sensor):

```
configure terminal
monitor session 1 source interface fa0/1 both
monitor session 1 source interface g0/1 both
monitor session 1 destination interface fa0/24
end
write memory
```

CORE1 (mirror the firewall inside link to the core sensor):

```
configure terminal
monitor session 1 source interface fa0/20 both
monitor session 1 destination interface fa0/21
end
write memory
```

**Check:** `show etherchannel summary` on a core shows Po1 with both ports bundled (flags `SU` and `P`). `show spanning-tree vlan 10` shows one core as root. `show monitor session 1` lists the expected sources and destination.

### Stage 4: layer-3 core, HSRP gateways and inter-VLAN routing

**On CORE1** (HSRP priority 110 makes it active for VLANs 10, 30 and 100; default 100 leaves CORE2 active for 20 and 50):

```
configure terminal
ip routing
interface loopback0
 ip address 10.254.0.1 255.255.255.255
interface vlan 10
 ip address 10.10.10.2 255.255.255.0
 standby 10 ip 10.10.10.1
 standby 10 priority 110
 standby 10 preempt
interface vlan 20
 ip address 10.10.20.2 255.255.255.0
 standby 20 ip 10.10.20.1
 standby 20 preempt
interface vlan 30
 ip address 10.10.30.2 255.255.255.0
 standby 30 ip 10.10.30.1
 standby 30 priority 110
 standby 30 preempt
interface vlan 50
 ip address 10.10.50.2 255.255.255.0
 standby 50 ip 10.10.50.1
 standby 50 preempt
interface vlan 100
 ip address 10.10.100.2 255.255.255.248
 standby 100 ip 10.10.100.1
 standby 100 priority 110
 standby 100 preempt
interface g0/1
 no switchport
 ip address 10.255.0.2 255.255.255.252
 no shutdown
end
write memory
```

**On CORE2:** the same, with addresses `.3` in every VLAN, `standby priority 110` on VLANs 20 and 50 (not 10, 30, 100), loopback `10.254.0.2`, and `g0/1` as `10.255.0.6/30`.

HSRP gives every VLAN a gateway (.1) that survives the loss of one core. Priorities are split so the two cores share the forwarding load in normal operation.

**Check:** `show standby brief` on each core lists it as Active for its VLANs and Standby for the rest. A staff PC (after stage 8) can ping 10.10.20.1.

### Stage 5: dynamic routing with OSPF

OSPF in a single area keeps the interior routing self-updating: a new branch or subnet is advertised automatically, with no static routes to edit at headquarters. The cores inject the default route so every site learns the path to the internet.

**On CORE1 and CORE2:**

```
configure terminal
router ospf 1
 router-id 10.254.0.1
 passive-interface default
 no passive-interface g0/1
 network 10.10.0.0 0.0.255.255 area 0
 network 10.255.0.0 0.0.0.255 area 0
 default-information originate
ip route 0.0.0.0 0.0.0.0 10.10.100.6
end
write memory
```

Use router-id `10.254.0.2` on CORE2. `passive-interface default` stops OSPF hellos on the user VLANs (nothing there speaks OSPF) while still advertising those subnets. The static default points at the firewall; `default-information originate` shares it with the rest of the network.

**On R-WAN:**

```
configure terminal
interface loopback0
 ip address 10.254.0.3 255.255.255.255
interface g0/0/0
 ip address 10.255.0.1 255.255.255.252
 no shutdown
interface g0/0/1
 ip address 10.255.0.5 255.255.255.252
 no shutdown
interface g0/0/2
 ip address 10.255.1.1 255.255.255.0
 no shutdown
router ospf 1
 router-id 10.254.0.3
 passive-interface g0/0/2
 network 10.255.0.0 0.0.0.255 area 0
 network 10.254.0.3 0.0.0.0 area 0
end
write memory
```

**On R-BR1** (router-on-a-stick for the branch VLANs; OSPF to headquarters over the WAN):

```
configure terminal
interface loopback0
 ip address 10.254.0.21 255.255.255.255
interface g0/0/0
 ip address 10.255.1.21 255.255.255.0
 no shutdown
interface g0/0/1
 no shutdown
interface g0/0/1.10
 encapsulation dot1q 10
 ip address 10.21.10.1 255.255.255.0
interface g0/0/1.20
 encapsulation dot1q 20
 ip address 10.21.20.1 255.255.255.0
router ospf 1
 router-id 10.254.0.21
 passive-interface default
 no passive-interface g0/0/0
 network 10.21.0.0 0.0.255.255 area 0
 network 10.255.1.0 0.0.0.255 area 0
end
write memory
```

The WAN segment 10.255.1.0/24 is shared, so R-WAN forms an OSPF adjacency with every branch router on one interface. Adding branch 2 needs no change on R-WAN.

**Check:** `show ip ospf neighbor` on R-WAN lists CORE1, CORE2 and R-BR1. `show ip route ospf` on CORE1 shows the branch subnets (10.21.x.0) and R-BR1 shows a default route (O*E2) learned from the cores.

### Stage 6: redundant internet edge

**On ISP** (models the provider; a static route back to the enterprise via the HSRP address):

```
configure terminal
interface g0/0/0
 ip address 203.0.113.1 255.255.255.252
 no shutdown
interface g0/0/1
 ip address 203.0.113.5 255.255.255.252
 no shutdown
interface g0/0/2
 ip address 203.0.113.129 255.255.255.128
 no shutdown
ip route 198.51.100.0 255.255.255.248 203.0.113.2
ip route 198.51.100.0 255.255.255.248 203.0.113.6 5
end
write memory
```

The second route has cost 5, so it is a floating backup: the ISP reaches the firewall through R-EDGE1 normally and R-EDGE2 if the first link fails.

**On R-EDGE1** (active HSRP, priority 110 with tracking):

```
configure terminal
interface g0/0/0
 ip address 203.0.113.2 255.255.255.252
 no shutdown
interface g0/0/1
 ip address 198.51.100.2 255.255.255.248
 standby 1 ip 198.51.100.1
 standby 1 priority 110
 standby 1 preempt
 standby 1 track g0/0/0 20
 no shutdown
ip route 0.0.0.0 0.0.0.0 203.0.113.1
end
write memory
```

**On R-EDGE2:** the same with `g0/0/0` as `203.0.113.6/30`, `g0/0/1` as `198.51.100.3/29`, default HSRP priority (100), and `ip route 0.0.0.0 0.0.0.0 203.0.113.5`. Interface tracking on R-EDGE1 lowers its priority if its uplink to the ISP drops, so R-EDGE2 takes over the virtual gateway.

**Check:** `show standby brief` on R-EDGE1 shows it Active for the .1 address. EXT-CLIENT can ping 198.51.100.1.

### Stage 7: ASA firewall

The ASA is configured through its CLI (double-click FW, **CLI** tab). It has three zones with security levels: outside (0), dmz (50), inside (100). Traffic from a higher level to a lower one is allowed by default; the reverse needs an explicit rule.

```
enable
configure terminal
hostname FW
interface g1/1
 nameif outside
 security-level 0
 ip address 198.51.100.6 255.255.255.248
 no shutdown
interface g1/2
 nameif inside
 security-level 100
 ip address 10.10.100.6 255.255.255.248
 no shutdown
interface g1/3
 nameif dmz
 security-level 50
 ip address 172.16.10.1 255.255.255.0
 no shutdown
route outside 0.0.0.0 0.0.0.0 198.51.100.1
route inside 10.0.0.0 255.0.0.0 10.10.100.1
object network WEB
 host 172.16.10.10
access-list OUTSIDE_IN extended permit tcp any host 172.16.10.10 eq www
access-list OUTSIDE_IN extended permit icmp any any echo-reply
access-group OUTSIDE_IN in interface outside
end
write memory
```

The static route `10.0.0.0/8 via 10.10.100.1` sends all internal traffic to the HSRP address of the cores, so the firewall reaches every campus and branch subnet through one route. The access list lets external clients reach only the web server on TCP 80; that is the north-south traffic NIDS-DMZ inspects.

**Check:** `show route` on the ASA lists the default via outside and 10.0.0.0/8 via inside. EXT-CLIENT can load `http://172.16.10.10`; a ping from EXT-CLIENT to a staff PC fails (outside cannot reach inside).

### Stage 8: branch access, DHCP and services

**BR-SW1** (branch access switch, trunk to the branch router):

```
configure terminal
vtp mode transparent
vlan 10
 name MGMT
vlan 20
 name STAFF
vlan 99
 name NATIVE
spanning-tree mode rapid-pvst
interface g0/1
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 10,20,99
interface range fa0/1 - 8
 switchport mode access
 switchport access vlan 20
 spanning-tree portfast
end
write memory
```

**Central DHCP.** Configure pools on SRV-CORE (**Services > DHCP**): one pool per user VLAN, each with the VLAN's gateway (.1) as the default gateway and 10.10.50.10 as the DNS server. So the server's replies reach every VLAN, add a relay on each user SVI on both cores and on the branch router subinterfaces:

```
! on CORE1 and CORE2
configure terminal
interface vlan 20
 ip helper-address 10.10.50.10
interface vlan 30
 ip helper-address 10.10.50.10
end
! on R-BR1
configure terminal
interface g0/0/1.20
 ip helper-address 10.10.50.10
end
```

For the branch pool to work, add a pool for 10.21.20.0/24 on SRV-CORE as well. A single DHCP server therefore addresses every site.

**Services on the server farm** (each on its Server-PT device, **Services** tab): SRV-CORE runs DHCP, DNS (an A record `web.netra.lab` to 172.16.10.10) and NTP; SRV-LOG runs Syslog; NETRA-CONSOLE runs no Packet Tracer service (it represents the host running the desktop app, which in the real lab connects to the sensors over the management VLAN).

**Check:** set each user PC to DHCP (**Desktop > IP Configuration > DHCP**) and confirm it receives an address in the right subnet with the correct gateway. A staff PC can ping the branch PC, proving end-to-end routing across the WAN.

### Stage 9: verify the whole network

Run these from a staff PC unless noted:

| Test | Expected result |
|---|---|
| `ping 10.10.20.1` | gateway replies (local HSRP address) |
| `ping 10.21.20.100` | branch PC replies (OSPF path over the WAN) |
| `ping 172.16.10.10` | web server replies (inside to DMZ through the firewall) |
| browse `http://web.netra.lab` | page loads (DNS plus firewall plus routing) |
| from EXT-CLIENT, browse `http://172.16.10.10` | loads (permitted north-south) |
| from EXT-CLIENT, `ping 10.10.20.100` | fails (firewall blocks outside to inside) |
| unplug CORE1 Fa0/1 uplink | staff PC keeps its gateway (HSRP and the second uplink) |
| `show ip route ospf` on a core | branch and WAN subnets present |

Save as `netra_topology.pkt` and use **File > Print** or a screenshot for the slides.

## 6. Demonstrating detection and response

1. Switch to **Simulation** mode (bottom right).
2. In **Edit Filters**, show only HTTP, TCP and ICMP.
3. From EXT-CLIENT, send an HTTP request to 172.16.10.10 and press **Play**.
4. Trace the path: EXT-CLIENT, ISP, R-EDGE1, SW-OUT, FW outside, FW dmz, SW-DMZ, WEB. Point out that SW-DMZ copies each frame to Fa0/24, where NIDS-DMZ analyses it. A second flow from a staff PC to the internet is copied to NIDS-CORE at the core, showing the two sensors cover different traffic.
5. To model Netra's response, add a temporary deny on the ASA for the attacker, standing in for the block the real engine applies:
   ```
   access-list OUTSIDE_IN line 1 extended deny ip host 203.0.113.200 any
   ```
   Replay the request from ATTACKER and show it is dropped at the firewall. Remove it afterwards:
   ```
   no access-list OUTSIDE_IN line 1 extended deny ip host 203.0.113.200 any
   ```

This mirrors how a passive sensor works in production: it detects on mirrored traffic and asks the firewall (or a switch ACL) to enforce the block. In the Docker lab the sensor enforces the block itself, because it shares the protected server's namespace.

## 7. Scaling the design

Each kind of growth follows a fixed template, which is the point of the hierarchical addressing and the collapsed core.

**Add an access switch (more users at headquarters).**
1. Place a 2960, apply the stage 2 baseline and the stage 3 access template unchanged.
2. Cable Gi0/1 to the next free CORE1 port and Gi0/2 to the same port on CORE2, both cross-over.
3. Nothing else changes: the cores already trunk and route those VLANs, and OSPF already advertises them. Capacity for about ten more access switches exists on the core ports as listed; beyond that, move to distribution switches per building (see below).

**Add a user VLAN (say VLAN 40, LAB, 10.10.40.0/24).**
1. `vlan 40` on the cores and any access switch that needs it; add 40 to the relevant trunk allowed lists.
2. On both cores, add an SVI `vlan 40` with HSRP `.1` and an `ip helper-address`, splitting the active role between the cores as before.
3. Add a DHCP pool on SRV-CORE. OSPF advertises 10.10.40.0/24 automatically because it falls inside the existing `network 10.10.0.0 0.0.255.255` statement.

**Add a branch (branch 2, 10.22.0.0/16).**
1. Place R-BR2, BR-SW2 and the branch PCs. Give R-BR2 loopback 10.254.0.22 and WAN address 10.255.1.22/24.
2. Apply the R-BR1 configuration with the 10.22.x subnets and router-id 10.254.0.22.
3. Cable R-BR2 to a free SW-WAN port. R-WAN forms the OSPF adjacency automatically over the shared WAN segment, and headquarters learns 10.22.0.0/16 with no change at the core. Add its DHCP pool on SRV-CORE.

**Add a Netra sensor (new monitored choke point).**
1. Place a Server-PT with a second NIC.
2. On the switch at that choke point, add a SPAN session with the link to watch as source and the sensor's capture port as destination.
3. Put the sensor's management port in VLAN 10 and point the engine at NETRA-CONSOLE. The sensors are independent, so any number can report to one console.

**Grow the core into a three-tier design.** When one building's access switches exceed the core's ports, insert a pair of distribution switches per building: access switches home to the distribution pair, the distribution pair connects to the two cores, and OSPF areas can be introduced (one area per building, area 0 on the core) so each building's link changes stay local. The addressing plan already supports this: give each building its own second-octet or third-octet block and summarise at the distribution layer.

**Add NAT for a realistic edge.** On the ASA, `object network INSIDE-PAT` with `nat (inside,outside) dynamic interface` gives inside users PAT, and a static NAT on the WEB object publishes the server on a public address. This changes only the firewall, not the interior.

## 8. Mapping to the Netra Docker lab

| Packet Tracer | Docker lab | Notes |
|---|---|---|
| ATTACKER (203.0.113.200) | `attacker` 10.77.0.66 | testing tools, run only inside the lab |
| WEB in DMZ (172.16.10.10) | `victim` 10.77.0.10 (nginx) | page at `/`, login at `/admin/` |
| NIDS-DMZ on the SPAN port | `nids` sharing the victim's namespace | sees every victim packet, like a SPAN copy |
| NIDS-CORE on the core SPAN | (not in the lab) | second sensor; the lab models the DMZ sensor |
| NETRA-CONSOLE | the host running `python -m src.cli app` | connects to the engine's event API |
| Firewall deny rule | iptables `NETRA` chain in the victim namespace | added and removed automatically with a timer |
| DMZ and VLANs | Docker network `lab` 10.77.0.0/24 (internal) | isolated, no route out |
| Management VLAN 10 | Docker network `mgmt`, ports bound to 127.0.0.1 | the desktop app connects here |

The lab implements one sensor (the DMZ one) end to end. The Packet Tracer diagram shows where that sensor sits in a full network and where a second sensor would go. The detection logic is identical in both; only the enforcement point differs (firewall or switch ACL in production, in-namespace iptables in the lab).

## 9. Packet Tracer limitations

- Packet Tracer accepts SPAN (`monitor session`) commands but does not show the mirrored copies moving in simulation mode. The session documents the design; the Docker lab performs the real capture.
- The ASA models core features only. Advanced inspection and some NAT forms behave differently from a real appliance.
- HSRP, OSPF, EtherChannel and Rapid PVST+ are simulated faithfully enough for the failover and convergence checks in this guide, but timers and corner cases may differ from hardware.
- Throughput and the ML detection itself cannot be modelled in Packet Tracer. Use it for topology, addressing, routing and traffic paths, and use the Docker lab and `reports/RESULTS.md` for detection behaviour and measured performance.
