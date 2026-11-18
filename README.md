# SDN Dynamic Firewall with Security Event Logger

A multithreaded TCP network security application built for **Computer Networks (UE25CS243A)**[cite: 3, 19]. This project integrates low-level POSIX socket programming in C with a Mininet-emulated Software-Defined Network (SDN) and Open vSwitch to dynamically inspect payloads, log intrusion events, and isolate malicious hosts at the switch layer[cite: 1, 19, 20].

## System Architecture

The network topology consists of four Linux network namespaces connected to a single Open vSwitch (`s1`) operating with OpenFlow[cite: 3, 20]:

* **`h1` (`10.0.0.1`):** Legitimate TCP client generating normal application requests (`HELLO_DATA_REQ`)[cite: 20].
* **`h2` (`10.0.0.2`):** Attacker TCP client transmitting unauthorized payloads (`ATTACK_PAYLOAD`)[cite: 20].
* **`h3` (`10.0.0.3:8080`):** Multithreaded TCP Application Server that inspects incoming socket buffers[cite: 20]. Upon detecting malicious signatures, it rejects the connection (`403 Forbidden`), alerts the logging daemon, and injects a dynamic OpenFlow drop rule into `s1`[cite: 20, 26, 27].
* **`h4` (`10.0.0.4:9999`):** Centralized Security Event Logger daemon that records timestamped intrusion alerts to disk (`security_events.log`) and console[cite: 1, 20].

## Key Features

* **Low-Level TCP Sockets:** Built in C using `<sys/socket.h>` and `<arpa/inet.h>` with custom application-level messaging[cite: 2, 21].
* **Concurrent Request Handling:** Uses POSIX threads (`pthread`) to handle multiple simultaneous client connections without blocking[cite: 21, 23].
* **Dynamic SDN Mitigation:** Translates Layer 7 payload inspection into Layer 2/Layer 3 OpenFlow rules (`ovs-ofctl`) to drop attacker traffic directly at the virtual switch[cite: 27].
* **Automated Recovery:** Enforces drop rules with a `hard_timeout=30`, automatically evicting the block after 30 seconds to restore connectivity[cite: 1, 28].

## Repository Structure

* `app_server.c` – Multithreaded TCP server with payload inspection and OpenFlow rule trigger[cite: 20, 21].
* `logger_server.c` – Centralized TCP logging server for recording security violations[cite: 20, 21].
* `client.c` – TCP client utility for simulating normal and malicious traffic[cite: 20, 21].
* `topo.py` – Custom Mininet Python topology script defining `s1` and hosts `h1`–`h4`[cite: 20, 22].

## Prerequisites

* Ubuntu Linux (20.04 / 22.04 LTS or newer)[cite: 3]
* `mininet` & `openvswitch-switch`[cite: 4, 7]
* `gcc` (with `pthread` support) & `xterm`
* `wireshark` (for packet and OpenFlow verification)[cite: 6, 28]

## Quick Start & Execution

### 1. Compile the C Programs
```bash
gcc -Wall -Wextra -pthread logger_server.c -o logger_server
gcc -Wall -Wextra -pthread app_server.c -o app_server
gcc -Wall -Wextra client.c -o client
