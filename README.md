# TINT

**TINT** (**T**raffic **I**ntent to **N**etwork **T**ables), is a proof-of-concept (PoC) daemon and [Containerlab](https://containerlab.dev/) testbed for dynamically steering traffic into SRv6 Policies using **BGP Flowspec** and **PCEP**.

## Overview

In this architecture, traffic classification rules and SRv6 paths are provisioned independently and bound together inside the headend router (`router1`) via Linux kernel routing tables and Policy-Based Routing (PBR):

1. **SRv6 Policy Provisioning (PCEP)**:
   [Pola PCE](https://github.com/nttcom/pola) pushes explicit SRv6 segment lists to [OpenPCC](https://github.com/Azunyan19/OpenPCC) running on `router1`. OpenPCC installs `encap seg6 mode encap` routes into dedicated Linux routing tables (`table 100` for `router3` path, `table 200` for `router4` path).
2. **Flow Classification & Binding (BGP Flowspec)**:
   An external GoBGP route server advertises IPv4 Flowspec rules (5-tuple match + BGP Color Extended Community) to `router1`.
3. **Validation & Alerting (`prism`)**:
   `prism` monitors GoBGP RIB events via gRPC, checks whether the corresponding SRv6 Policy table exists in the kernel via Netlink, and installs `ip rule` (PBR) entries. If a referenced SRv6 Policy table does not exist, it blocks PBR installation and sends a warning alert to a remote Syslog server.

## Topology

<img width="1280" height="720" alt="topology" src="https://github.com/user-attachments/assets/e7566647-7cae-43dd-96f5-d8cad835815c" />


## Directory Structure

* `cmd/tint/`: Go daemon (`tint`) that binds BGP Flowspec rules (Color) to kernel routing tables via Netlink PBR (`ip rule`).
* `openpcc/`: Modified version of [OpenPCC](https://github.com/fukuda-lab/OpenPCC) (`simple-pcc` branch) extended to support Pola PCE session synchronization and `seg6 mode encap` route injection into specific routing tables.
* `configs/`: Configuration files for GoBGP, Pola PCE, and node initialization scripts.
* `Dockerfile`: Container image definition for SRv6 routers (`srv6-router:latest`).
* `topo.yaml`: Containerlab topology definition.

## Quick Start

### 1. Build Router Image and Binaries

    make image
    make

### 2. Deploy Containerlab Topology

    sudo containerlab deploy -t topo.yaml

### 3. Start OpenPCC on `router1` and Provision SRv6 Policies from Pola PCE

Terminal 1 (Start OpenPCC):

    docker exec -it clab-srv6-lab-router1 srv6-pcc -p 172.20.20.30 -l 172.20.20.100 -i eth1

Terminal 2 (Push SR Policies from Pola):

    docker exec -it clab-srv6-lab-pola pola sr-policy add --no-sid-validate -f /pola/policy-color100.yaml
    docker exec -it clab-srv6-lab-pola pola sr-policy add --no-sid-validate -f /pola/policy-color200.yaml

### 4. Start `tint` and Advertise Flowspec Rules

Terminal 3 (Start `tint` on `router1`):

    docker exec -it clab-srv6-lab-router1 tint

Terminal 2 (Inject Flowspec rules from `gobgp-server`):

    # Steer TCP port 80 traffic to Color 100 (Table 100 -> via router3)
    docker exec -it clab-srv6-lab-gobgp-server gobgp global rib -a ipv4-flowspec add match destination 192.168.2.1/32 protocol tcp destination-port '=80' then color 100

    # Steer TCP port 443 traffic to Color 200 (Table 200 -> via router4)
    docker exec -it clab-srv6-lab-gobgp-server gobgp global rib -a ipv4-flowspec add match destination 192.168.2.1/32 protocol tcp destination-port '=443' then color 200

    # Test missing SR Policy alert (Color 300 -> triggers remote Syslog alert)
    docker exec -it clab-srv6-lab-gobgp-server gobgp global rib -a ipv4-flowspec add match destination 192.168.2.1/32 protocol tcp destination-port '=8080' then color 300

Check remote Syslog alerts:

    docker exec -it clab-srv6-lab-syslog cat /var/log/syslog_alert.log

## Acknowledgments & License

* This project is licensed under the MIT License (see [LICENSE](./LICENSE)).
* The `openpcc/` directory contains a modified version of [OpenPCC](https://github.com/fukuda-lab/OpenPCC) originally developed by Taisei Tanabe (`Azunyan19`) under the MIT License (see `openpcc/LICENSE`).
