# SadDNS

This repository attempts to reproduce crucial parts of the [SadDNS](https://www.saddns.net/) attack.
In particular, the repository contains a Python script for performing the novel UDP port scan which exploits the Linux kernel's insufficient randomisation of the ICMP error rate limit parameters to determine an open UDP port on a DNS resolver.
Once the open UDP source port on the resolver has been found, malicious DNS answers, which try to guess the DNS transaction ID, are sent to the DNS resolver.

## Background



## Test Network Architecture
