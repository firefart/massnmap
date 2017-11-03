# MASSNMAP

This little script gets all DNS A records for a given zone via zone transfer (your machine must be allowed for it),
gathers all open ports via massscan and then fires up single nmap scans for version detection and scripts of the single hosts.
The output is saved in various files and all NMAP xml outputs are stored in the results folder for further processing.

To configure the scan modify the provided `scan.cfg.example` and pass it via the `-c parameter`

## Requirements
- Python3
- massscan
- nmap

## Sample
```
./run.py -c scan.cfg
```
