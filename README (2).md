# Network Traffic Analysis Using Wireshark

## Project Overview

This project documents a hands-on network traffic investigation using
**Wireshark** and **Nmap** on a Windows host. The objective was to
identify active services, inspect network conversations, and understand
packet-level indicators such as TCP retransmissions, duplicate
acknowledgements, resets, and DNS activity.

> **Scope note:** The observations below describe what was visible in
> the supplied screenshots. A retransmission, duplicate ACK, or TCP
> reset is not by itself proof of an attack. The evidence reviewed here
> does not establish malicious activity.

## Tools Used

-   **Wireshark** --- packet capture and protocol analysis
-   **Nmap** --- host and service discovery
-   **Windows Command Prompt / PowerShell** --- process, port, and
    firewall inspection

## Investigation Environment

-   Operating system identified by Nmap: Windows
-   Host investigated: `192.168.31.64`
-   Hostname reported by Nmap: `Aditya.lan`
-   Capture size shown in Wireshark: 25,197 packets

## 1. Nmap Host and Service Discovery

The command used:

``` bash
nmap -sV -T2 192.168.31.64
```

The host was reachable. The scan reported these open TCP ports:

  -----------------------------------------------------------------------
  Port                    Service /               Notes
                          identification reported 
  ----------------------- ----------------------- -----------------------
  135/tcp                 msrpc --- Microsoft     Windows RPC service
                          Windows RPC             

  139/tcp                 netbios-ssn ---         NetBIOS session service
                          Microsoft Windows       
                          netbios-ssn             

  445/tcp                 microsoft-ds?           SMB-related service
                                                  identification

  903/tcp                 ssl/vmware-auth ---     Nmap service
                          VMware Authentication   identification
                          Daemon 1.10             

  8000/tcp                http-alt --- Splunkd    Splunk service
                                                  identified by Nmap

  8089/tcp                unknown                 Open; service not
                                                  identified by Nmap
  -----------------------------------------------------------------------

The scan reported 9,994 closed TCP ports.

## 2. Process and Listening-Port Verification

The following command was used to identify the process listening on port
8089:

``` cmd
netstat -ano | findstr :8089
```

The output showed:

-   `0.0.0.0:8089` in the `LISTENING` state
-   PID `6844`

The PID was checked with:

``` cmd
tasklist /fi "PID eq 6844"
```

The process was reported as:

``` text
splunkd.exe
PID 6844
```

A check of port 8000 also showed PID `6844` listening on `0.0.0.0:8000`.
This links both listening ports to the `splunkd.exe` process in the
captured command output.

## 3. Windows Firewall Review

The Windows Firewall output showed the Domain, Private, and Public
profiles enabled. The displayed default firewall policy was:

-   Block inbound connections that are not allowed
-   Allow outbound connections

The available screenshots did not establish a specific enabled inbound
firewall rule for ports 8000 or 8089. The firewall review therefore
remains a configuration observation, not proof that either port is
exposed to every network.

## 4. TCP Analysis in Wireshark

The following Wireshark display filters were used:

``` text
tcp.analysis.retransmission
tcp.analysis.fast_retransmission
tcp.analysis.duplicate_ack
tcp.flags.reset == 1
```

### Observations

-   Wireshark displayed TCP retransmission events in several
    conversations.
-   Duplicate ACK events were visible, including repeated
    acknowledgements in a TCP conversation between `192.168.31.64` and
    `104.18.32.47`.
-   A fast retransmission was visible from `104.18.32.47` to
    `192.168.31.64` over TCP port 443.
-   A TCP RST packet was visible in an IPv6 conversation between two
    external IPv6 addresses.

### Interpretation

TCP retransmissions and duplicate ACKs can occur when packets are lost,
delayed, or received out of order. A reset packet can indicate that a
connection was refused or terminated. These events merit context and
correlation, but the screenshots alone do not identify their root cause
or demonstrate malicious behavior.

One inspected packet showed a retransmitted TCP segment carrying TLS
application data. Since the payload was TLS-protected, the application
content was not readable in the packet view.

## 5. DNS Analysis

The following display filters were used:

``` text
dns
dns.flags.rcode != 0
dns.flags.response == 0
```

A DNS request for `www.msftncsi.com` was inspected.

The corresponding response showed:

-   DNS response with **No error (RCODE 0)**
-   Four answer records
-   A CNAME chain leading through `www.msftncsi.com.edgesuite.net` and
    `a1961.g2.akamai.net`
-   IPv4 address answers `49.44.179.139` and `49.44.179.136`
-   Response time shown by Wireshark: approximately 21.5 ms

The non-zero response-code filter returned no displayed packets in the
reviewed capture view. This means no matching DNS error responses were
shown by that filter in the capture; it does not prove that DNS errors
never occurred outside the captured traffic.

## 6. Outbound Connection Observations

A filter for outbound TCP traffic from the investigated host to ports
other than 80 and 443 showed repeated traffic to `192.168.31.130` on
port `8009`. The inspected packets included TLS application data and TCP
acknowledgements.

A separate conversation with `52.98.46.194` included a TLS Client Hello
with the SNI value `substrate.office.com`, followed by TLS handshake and
application-data packets. This is an observed encrypted TLS connection;
the screenshots do not reveal the encrypted application payload.

## 7. Findings Summary

  ------------------------------------------------------------------------
  Area                    Finding                  Assessment
  ----------------------- ------------------------ -----------------------
  Host discovery          `192.168.31.64` was up   Confirmed by Nmap

  Open services           Ports 135, 139, 445,     Services should be
                          903, 8000, and 8089 were reviewed against the
                          reported open            host's intended role

  Splunk process          PID 6844 (`splunkd.exe`) Confirmed by `netstat`
                          listened on ports 8000   and `tasklist`
                          and 8089                 screenshots

  Firewall                Firewall profiles were   Review of specific
                          enabled; inbound default rules was inconclusive
                          policy blocked           
                          unsolicited inbound      
                          traffic                  

  TCP behavior            Retransmissions,         Potential
                          duplicate ACKs, fast     network-quality /
                          retransmission, and one  connection-management
                          RST were observed        indicators; not proof
                                                   of an attack

  DNS                     `www.msftncsi.com`       No DNS error shown for
                          resolved successfully    this request
                          through an Akamai CNAME  
                          chain                    

  TLS                     A TLS Client Hello used  Encrypted traffic;
                          SNI                      payload not inspected
                          `substrate.office.com`   
  ------------------------------------------------------------------------

## 8. Recommendations / Next Steps

1.  Confirm that Splunk is intended to listen on ports 8000 and 8089 and
    restrict access to trusted management networks.
2.  Review the effective Windows Firewall inbound rules for ports 8000
    and 8089 using the exact rule details, rather than relying only on
    the default profile policy.
3.  Investigate retransmission and duplicate-ACK patterns by following
    each TCP stream and checking whether the events are repeated,
    persistent, or associated with user-visible connectivity problems.
4.  Identify the process and purpose of other open services, especially
    ports 903 and 445, and disable services that are not required.
5.  Preserve a sanitized capture and screenshots if the project is to be
    shared publicly. Remove personal identifiers and sensitive internal
    network information first.

## 9. Conclusion

The investigation identified several open services on the Windows host
and confirmed that the Splunk process was listening on ports 8000 and
8089. Wireshark analysis showed normal DNS resolution for the inspected
Microsoft connectivity-check domain, encrypted TLS communication, and
several TCP conditions including retransmissions, duplicate
acknowledgements, and a reset packet.

Based on the screenshots reviewed, these are **observations for further
investigation**, not confirmed security incidents. Additional endpoint
logs, firewall rule details, and repeated captures would be required to
determine whether any of the network events indicate a security issue.

------------------------------------------------------------------------

## Evidence Checklist

Add sanitized screenshots to the `Screenshots/` folder and refer to them
here:

-   [ ] Nmap service scan
-   [ ] `netstat` and `tasklist` process verification
-   [ ] Windows Firewall profile output
-   [ ] Wireshark TCP retransmission / duplicate ACK evidence
-   [ ] Wireshark TCP reset evidence
-   [ ] DNS request and successful response
-   [ ] TLS Client Hello / SNI evidence

**Privacy reminder:** Do not publish an unredacted PCAP file or
screenshots containing personal device identifiers, usernames, public
IPs tied to your activity, or sensitive network details. Share only
traffic you own or are authorized to analyze.
