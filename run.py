#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from datetime import datetime
from multiprocessing import cpu_count, Pool, current_process
import logging
import re
import subprocess
import tempfile
from collections import namedtuple
import sys
import ipaddress
import json
from pathlib import Path

VERSION = "1.0"
LOG_FORMAT = "%(asctime)-15s - %(levelname)-8s - %(processName)-11s - %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

NUM_WORKERS = cpu_count() * 5

Port = namedtuple("Port", ["protocol", "port"])

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

def wf(fname, content):
    with open(fname, "wt") as f:
        f.write(content)

def rf(fname):
    with open(fname, "rt") as f:
        return f.read()

def extract_string(r, string):
    m = re.search(r, string)
    if m:
        return m.group(1)
    else:
        return ""

def calculate_timedelta(time1):
    now = datetime.now()
    return now - time1

def execute_process(c, shell=False):
    logger.debug("Executing {}".format(c))
    # Needed when shell = False
    if (shell == False and type(c) is str):
        c = c.split()
    try:
        output = subprocess.check_output(c, stderr=subprocess.STDOUT, shell=shell)
    except subprocess.CalledProcessError as e:
        logger.error("Error when running {}: {}".format(c, e.output))
        output = e.output
    return output

def get_zones():
    a = execute_process("dig -t axfr {} | grep -E \"\s+NS\s+\" | awk '{{print $1}}' | sort -u | sed -r \"s/\.$//\"".format(ROOT_ZONE), True)
    x = a.strip().split(b"\n")
    return [y.decode("utf-8") for y in x]

def get_a_records(zone):
    zone = zone if isinstance(zone, str) else zone.decode('utf-8')
    a = execute_process("dig -t axfr {} | grep -E \"\s+A\s+\" | awk '{{print $5}}' | sort -V".format(zone), True)
    x = a.strip().split(b"\n")
    return [y.decode("utf-8") for y in x]

def parse_nmap_services(filename):
    ports = []
    content = rf(filename)
    # only use tcp
    for line in content.splitlines():
        if "/tcp" not in line:
            continue
        port = extract_string(r"\s+(\d+)/tcp\s+", line)
        if port == "":
            continue
        ports.append(port)
    return ports

def generate_massscan_config(ports_to_scan, file_in, file_out):
    return ("rate = 100000.00\n"
            "randomize-hosts = true\n"
            "show = open\n"
            "ports = {ports}\n"
            "includefile = {infile}\n"
            "output-format = list\n"
            "output-filename = {outfile}\n").format(
                ports=",".join(ports_to_scan),
                infile=file_in,
                outfile=file_out
            )

def start_massscan(records, ports):
    with tempfile.NamedTemporaryFile() as input_file, tempfile.NamedTemporaryFile() as output_file, tempfile.NamedTemporaryFile() as config_file:
        for r in records:
            line = "{0}\n".format(r.strip()).encode("utf-8")
            input_file.write(line)
        input_file.flush()

        config = generate_massscan_config(ports, input_file.name, output_file.name)
        config_file.write(config.encode("utf-8"))
        config_file.flush()

        a = execute_process("masscan -c {}".format(config_file.name))
        output_file.flush()
        output_file.seek(0)
        output = output_file.read()
    return output

def parse_massscan_output(output):
    ret = {}
    for line in output.splitlines():
        line = line.decode("utf-8")
        if line.startswith("#"):
            continue
        # Format: open proto port ip timestamp
        m = re.search(r"^open\s+(\w+)\s+(\d+)\s+([\w\.]+)\s+\d+$", line)
        if m:
            proto = m.group(1)
            port = int(m.group(2))
            ip = m.group(3)
            if ip in ret:
                ret[ip].append(Port(port=port, protocol=proto))
            else:
                ret[ip] = [Port(port=port, protocol=proto)]
        else:
            print("No Regex Match at line " + line)
    return ret

def start_nmaps(item):
    start_time = datetime.now()
    ip = item[0]
    ports = item[1]
    if len(ports) == 0:
        logger.debug("No open ports for {}".format(ip))
        return
    ports = sorted(ports, key=lambda x: x.port)
    portmapping = ""
    uses_tcp = False
    uses_udp = False
    for p in ports:
        if p.protocol == "tcp":
            portmapping += "T:"
            uses_tcp = True
        elif p.protocol == "upd":
            portmapping += "U:"
            uses_udp = True
        else:
            logger.error("Unknown protocol {}".format(p.protocol))
        portmapping += str(p.port)
        portmapping += ","
    portmapping = portmapping.rstrip(",")

    scan_type = "-s"
    scan_type += ("S" if uses_tcp else "")
    scan_type += ("U" if uses_udp else "")
    scan_type += "V" # version detection
    with tempfile.NamedTemporaryFile() as output_file:
        nmap_command = "nmap -p {0} {1} -Pn -T5 -O -A --osscan-guess --host-timeout=10m -oN {2} -oX {3} --dns-servers {4} {5}".format(
                portmapping,
                scan_type,
                output_file.name,
                "results/" + ip + ".xml",
                DNS_SERVER,
                ip)
        a = execute_process(nmap_command)
        output_file.flush()
        output_file.seek(0)
        output = output_file.read()
    logger.debug("{} finished ({})".format(current_process().name, calculate_timedelta(start_time)))
    return output


def main(config_file):
    # 1) parse config file
    # 2) get zones
    # 3) extract all a records from zones
    # 4) parse nmap_services for top used ports and remove blacklisted ports
    # 5) massscan of a records
    # 6) parse massscan output
    # 7) run single nmap scans with discovered ports

    # 1
    p = Path(config_file)
    if not p.is_file():
        logger.error("{} is no valid file".format(config_file))
        return
    with p.open() as f:
        try:
            config = json.load(f)
        except json.decoder.JSONDecodeError as e:
            logger.error("Invalid config file: {}".format(e))
            return

    global ROOT_ZONE, BLACKLIST_PORTS, BLACKLIST_IP, BLACKLIST_PORTS, DNS_SERVER
    ROOT_ZONE = config["root_zone"]
    BLACKLIST_ZONES = config["blacklisted_zones"]
    BLACKLIST_IP = config["blacklisted_ips"]
    BLACKLIST_PORTS = config["blacklisted_ports"]
    DNS_SERVER = config["dns_server"]

    # 2
    zones = get_zones()
    # also append root zone (also contains A records)
    zones.append(ROOT_ZONE)
    tmp = len(zones)
    zones = [z for z in zones if z not in BLACKLIST_ZONES]
    logger.info("Removed {} blacklisted zones".format(tmp - len(zones)))
    wf("zones.txt", "\n".join(zones))
    logger.info("Got {} zones".format(len(zones)))

    # 3
    a_records = []
    for zone in zones:
        a_records.extend(get_a_records(zone))
    # remove duplicates
    a_records = list(set(a_records))
    # only use internal ips
    tmp = len(a_records)
    a_records = [i for i in a_records if i != "" and ipaddress.ip_address(i).is_private]
    logger.info("Removed {} non private ips".format(tmp - len(a_records)))
    # remove blacklisted IPs
    tmp = len(a_records)
    a_records = [i for i in a_records if i not in BLACKLIST_IP]
    logger.info("Removed {} blacklisted ips".format(tmp - len(a_records)))
    wf("a_records.txt", "\n".join(a_records))
    logger.info("Got {} A records".format(len(a_records)))

    # 4
    # https://github.com/nmap/nmap/blob/master/nmap-services
    ports = parse_nmap_services("nmap_services")
    # Blacklisted Ports
    ports = [x for x in ports if x not in BLACKLIST_PORTS]
    logger.info("Removed {} blacklisted ports".format(len(BLACKLIST_PORTS)))

    # 5
    start_time = datetime.now()
    logger.info("Starting masscan")
    massscan_output = start_massscan(a_records, ports)

    # 6
    ports = parse_massscan_output(massscan_output)
    logger.info("Massscan finished in {} seconds".format(calculate_timedelta(start_time)))

    # 7
    start_time = datetime.now()
    logger.info("Starting nmap armada")
    nmap_outputs = []
    with Pool(NUM_WORKERS) as pool:
        ips_to_scan = len(ports)
        for counter, output in enumerate(pool.imap_unordered(start_nmaps, ports.items()), 1):
            nmap_outputs.append(output)
            sys.stderr.write("\rNmap progress: {0:.2%} ({1}/{2})".format(counter/ips_to_scan, counter, ips_to_scan))
        sys.stderr.write("\n")
    logger.info("NMAP scan finished in {}".format(calculate_timedelta(start_time)))

    with open("output.txt", "wb") as f:
        for x in nmap_outputs:
            f.write(x)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="scan")
    parser.add_argument("-c", "--config", required=True, help="config file to use")
    parser.add_argument("-d", "--debug", action="store_true", help="set loglevel to DEBUG")
    parser.add_argument("--version", action="version", version="%(prog)s {}".format(VERSION))
    args = parser.parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    overall_start_time = datetime.now()
    try:
        main(args.config)
    finally:
        logger.info("script finished in {}".format(calculate_timedelta(overall_start_time)))

