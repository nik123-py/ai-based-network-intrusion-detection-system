# Cisco Packet Tracer topology guide

Packet Tracer saves networks in a proprietary binary `.pkt` format that cannot be generated from code, so this file is a build guide. Following it produces a topology that shows where Netra sits in a typical small enterprise network. Packet Tracer models the topology and the traffic paths. The real detection and response run in the Docker lab (see `DEMO_GUIDE.md`).

Tested layout: Packet Tracer 8.2. Device models are suggestions; any similar models work.

## 1. Target topology

```
  [Internet PC]  (external attacker / external client)
        |
   Gi0/0 203.0.113.2
  [R-EDGE  ISR4331]  edge router
   Gi0/1 10.0.0.1
        |
   outside 10.0.0.2
  [FW  ASA 5506-X]   firewall
   dmz 172.16.10.1   inside 192.168.10.1
        |                     |
  [SW-DMZ 2960]         [SW-CORE 2960]
   |      |               |      |      |
[WEB]  [NIDS]           [PC1]  [PC2]  [NIDS mgmt, optional]
 172.16.10.10  (SPAN destination, no IP on the sniffing port)
```

## 2. Addressing plan

| Device | Interface | Address | Gateway | VLAN |
|---|---|---|---|---|
| Internet PC | Fa0 | 203.0.113.10/24 | 203.0.113.2 | none |
| R-EDGE | Gi0/0 | 203.0.113.2/24 | none | none |
| R-EDGE | Gi0/1 | 10.0.0.1/30 | none | none |
| FW (ASA) | Gi1/1 outside | 10.0.0.2/30 | default route to 10.0.0.1 | none |
| FW (ASA) | Gi1/2 inside | 192.168.10.1/24 | none | none |
| FW (ASA) | Gi1/3 dmz | 172.16.10.1/24 | none | none |
| WEB (Server-PT) | Fa0 | 172.16.10.10/24 | 172.16.10.1 | 10 (DMZ) |
| NIDS (Server-PT) | Fa0 | no IP (sniffing port) | none | 10 (DMZ, SPAN destination) |
| PC1 | Fa0 | 192.168.10.21/24 | 192.168.10.1 | 20 (INSIDE) |
| PC2 | Fa0 | 192.168.10.22/24 | 192.168.10.1 | 20 (INSIDE) |

VLAN notes: the DMZ switch carries VLAN 10 for the web server, and the core switch carries VLAN 20 for clients. Each switch connects to one firewall interface as an access port, so no trunking is required. If you prefer a single switch, create VLAN 10 and VLAN 20 on it and use a trunk (`switchport mode trunk`) to a router-on-a-stick instead of the ASA.

## 3. Build steps

1. Open Packet Tracer and select **File > New**.
2. From **Network Devices > Routers**, drag an **ISR4331** onto the workspace. Rename it `R-EDGE` (click the label).
3. From **Network Devices > Security**, drag an **ASA 5506-X**. Rename it `FW`.
4. From **Network Devices > Switches**, drag two **2960-24TT** switches. Rename them `SW-DMZ` and `SW-CORE`.
5. From **End Devices**, drag:
   - one **PC** named `Internet PC`,
   - two **Server-PT** devices named `WEB` and `NIDS`,
   - two **PCs** named `PC1` and `PC2`.
6. Cable the devices with **Connections > Copper Straight-Through**:
   1. Internet PC Fa0 to R-EDGE Gi0/0/0.
   2. R-EDGE Gi0/0/1 to FW Gi1/1.
   3. FW Gi1/3 to SW-DMZ Gi0/1.
   4. FW Gi1/2 to SW-CORE Gi0/1.
   5. WEB Fa0 to SW-DMZ Fa0/1.
   6. NIDS Fa0 to SW-DMZ Fa0/24 (this becomes the SPAN destination).
   7. PC1 Fa0 to SW-CORE Fa0/1.
   8. PC2 Fa0 to SW-CORE Fa0/2.
7. Set the end-device addresses from the table in section 2. For each one, click the device, open **Desktop > IP Configuration** and enter the address, mask and gateway. Leave the NIDS unconfigured: a monitoring port normally has no IP address.
8. Configure R-EDGE. Click it, open **CLI**, and enter:
   ```
   enable
   configure terminal
   hostname R-EDGE
   interface g0/0/0
    ip address 203.0.113.2 255.255.255.0
    no shutdown
   interface g0/0/1
    ip address 10.0.0.1 255.255.255.252
    no shutdown
   ip route 192.168.10.0 255.255.255.0 10.0.0.2
   ip route 172.16.10.0 255.255.255.0 10.0.0.2
   end
   write memory
   ```
9. Configure the FW (ASA) in its **CLI**:
   ```
   enable
   configure terminal
   hostname FW
   interface g1/1
    nameif outside
    security-level 0
    ip address 10.0.0.2 255.255.255.252
    no shutdown
   interface g1/2
    nameif inside
    security-level 100
    ip address 192.168.10.1 255.255.255.0
    no shutdown
   interface g1/3
    nameif dmz
    security-level 50
    ip address 172.16.10.1 255.255.255.0
    no shutdown
   route outside 0.0.0.0 0.0.0.0 10.0.0.1
   access-list OUTSIDE_IN extended permit tcp any host 172.16.10.10 eq www
   access-list OUTSIDE_IN extended permit icmp any any
   access-group OUTSIDE_IN in interface outside
   end
   write memory
   ```
   The access list lets external clients reach only the web server on TCP 80. That is the traffic Netra inspects.
10. Configure SW-DMZ: VLAN and SPAN session. In its **CLI**:
    ```
    enable
    configure terminal
    hostname SW-DMZ
    vlan 10
     name DMZ
    interface range fa0/1 - 23
     switchport mode access
     switchport access vlan 10
    interface g0/1
     switchport mode access
     switchport access vlan 10
    ! Mirror the web server port and the firewall uplink to the NIDS port.
    monitor session 1 source interface fa0/1 both
    monitor session 1 source interface g0/1 both
    monitor session 1 destination interface fa0/24
    end
    write memory
    show monitor session 1
    ```
    `show monitor session 1` should list Fa0/1 and Gi0/1 as sources and Fa0/24 as the destination. Packet Tracer accepts SPAN commands but does not visualise mirrored copies in simulation mode. The session documents the design; the Docker lab performs the actual capture.
11. Configure SW-CORE for VLAN 20 in the same way (`vlan 20`, `name INSIDE`, access ports on Fa0/1 to Fa0/23 and Gi0/1).
12. Enable the web service: click **WEB**, then **Services > HTTP**, and make sure HTTP is **On**.
13. Test reachability: on Internet PC, open **Desktop > Web Browser** and browse to `http://172.16.10.10`. The default page should load. Pings from Internet PC to PC1 should fail, because the inside network is not reachable from outside.
14. Add annotation notes (**Place Note** tool) next to the NIDS: "Netra: SPAN destination, signatures + ML + autoencoder, blocks via firewall". Next to the attacker: "Docker lab attacker 10.77.0.66".
15. Save the file as `netra_topology.pkt`, then use **File > Print** (or a screenshot) to put the diagram in the slides.

## 4. Showing the detection path in simulation mode

1. Switch to **Simulation** mode (bottom right).
2. In **Edit Filters**, show only HTTP, TCP and ICMP.
3. From Internet PC, send an HTTP request to 172.16.10.10 (web browser) and press **Play**.
4. Point out the path: Internet PC, R-EDGE, FW outside, FW dmz, SW-DMZ, WEB. Explain that SW-DMZ copies each of these frames to Fa0/24, where Netra analyses them.
5. To model a response, add a temporary deny line to the ASA for the attacker, standing in for Netra's block:
   ```
   access-list OUTSIDE_IN line 1 extended deny ip host 203.0.113.10 any
   ```
   Repeat the request and show it is dropped at the firewall. Remove the line afterwards with `no access-list OUTSIDE_IN line 1 extended deny ip host 203.0.113.10 any`.

## 5. Mapping to the Docker lab

| Packet Tracer | Docker lab | Notes |
|---|---|---|
| Internet PC (203.0.113.10) | `attacker` 10.77.0.66 | runs nmap, hping3, slowhttptest, hydra |
| WEB server in DMZ (172.16.10.10) | `victim` 10.77.0.10 (nginx) | page at `/`, login at `/admin/` |
| NIDS on SPAN port | `nids` sharing the victim's network namespace | sees every victim packet, like a SPAN copy |
| Firewall deny rule | iptables `NETRA` chain inside the victim namespace | added and removed automatically with a timer |
| DMZ switch and VLAN 10 | Docker network `lab` 10.77.0.0/24 (internal) | isolated, no route out |
| Management access | Docker network `mgmt`, ports bound to 127.0.0.1 | the desktop app connects here |

One difference is worth stating in the presentation. On a real network, a SPAN-port NIDS is passive and asks the firewall to block (through an API or a management session). In the lab, the NIDS shares the protected server's network namespace, so it can apply the block itself. The detection logic is the same in both cases; only the enforcement point differs.
