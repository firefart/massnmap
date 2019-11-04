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
import json
from pathlib import Path
import os
from ipaddress import ip_network, ip_address

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
    logger.debug(f"Executing {c}")
    # Needed when shell = False
    if (shell == False and type(c) is str):
        c = c.split()
    try:
        output = subprocess.check_output(c, stderr=subprocess.STDOUT, shell=shell)
    except subprocess.CalledProcessError as e:
        logger.error(f"Error when running {c}: {e.output}")
        output = e.output
    return output

def get_zones():
    a = execute_process(f"dig -t axfr {ROOT_ZONE} | grep -E \"\s+NS\s+\" | awk '{{print $1}}' | sort -u | sed -r \"s/\.$//\"", True)
    x = a.strip().split(b"\n")
    return [y.decode("utf-8") for y in x]

def get_a_records(zone):
    zone = zone if isinstance(zone, str) else zone.decode('utf-8')
    a = execute_process(f"dig -t axfr {zone} | grep -E \"\s+A\s+\" | awk '{{print $5}}' | sort -V", True)
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
    ports = ",".join(ports_to_scan)
    return (
        "rate = 100000.00\n"
        "randomize-hosts = true\n"
        "show = open\n"
        f"ports = {ports}\n"
        f"includefile = {file_in}\n"
        "output-format = list\n"
        f"output-filename = {file_out}\n"
    )

def start_massscan(records, ports):
    with tempfile.NamedTemporaryFile() as input_file, tempfile.NamedTemporaryFile() as output_file, tempfile.NamedTemporaryFile() as config_file:
        for r in records:
            line = f"{r.strip()}\n".encode("utf-8")
            input_file.write(line)
        input_file.flush()

        config = generate_massscan_config(ports, input_file.name, output_file.name)
        config_file.write(config.encode("utf-8"))
        config_file.flush()

        execute_process(["masscan", "-c", config_file.name])
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
        logger.debug(f"No open ports for {ip}")
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
            logger.error(f"Unknown protocol {p.protocol}")
        portmapping += str(p.port)
        portmapping += ","
    portmapping = portmapping.rstrip(",")

    scan_type = "-s"
    scan_type += ("S" if uses_tcp else "")
    scan_type += ("U" if uses_udp else "")
    scan_type += "V" # version detection
    with tempfile.NamedTemporaryFile() as output_file:
        nmap_command = [
            "nmap", "-p" , portmapping,
            scan_type,
            "-Pn",
            "-T5",
            "-O",
            "-A",
            "--osscan-guess",
            "--host-timeout", "10m",
            "-oN", output_file.name,
            "-oX", f"results/{ip}.xml",
            "--dns-servers", DNS_SERVER,
            "--script-args", f"http.useragent=\"{USER_AGENT}\"",
            ip
        ]
        execute_process(nmap_command)
        output_file.flush()
        output_file.seek(0)
        output = output_file.read()
    process_name = current_process().name
    delta = calculate_timedelta(start_time)
    logger.debug(f"{process_name} finished ({delta})")
    return output


def main(config_file):
    # 1) parse config file
    # 2) get zones
    # 3) extract all a records from zones
    # 4) parse nmap_services for top used ports and remove blacklisted ports
    # 5) massscan of a records
    # 6) parse massscan output
    # 7) run single nmap scans with discovered ports
    # 8) run post scan scripts

    # 1
    p = Path(config_file)
    if not p.is_file():
        logger.error(f"{config_file} is no valid file")
        return
    with p.open() as f:
        try:
            config = json.load(f)
        except json.decoder.JSONDecodeError as e:
            logger.error(f"Invalid config file: {e}")
            return

    global ROOT_ZONE, BLACKLIST_PORTS, BLACKLIST_IP, BLACKLIST_PORTS, BLACKLIST_RANGES, DNS_SERVER, USER_AGENT
    ROOT_ZONE = config["root_zone"]
    BLACKLIST_ZONES = config["blacklisted_zones"]
    BLACKLIST_IP = config["blacklisted_ips"]
    BLACKLIST_PORTS = config["blacklisted_ports"]
    BLACKLIST_RANGES = config["blacklisted_ranges"]
    DNS_SERVER = config["dns_server"]
    USER_AGENT = config["user_agent"]
    POST_SCAN_SCRIPTS = config["post_scan_scripts"]

    # create results directory
    if not os.path.exists("results"):
        os.makedirs("results")

    # 2
    zones = get_zones()
    # also append root zone (also contains A records)
    zones.append(ROOT_ZONE)
    tmp = len(zones)
    zones = [z for z in zones if z not in BLACKLIST_ZONES]
    logger.info(f"Removed {tmp - len(zones)} blacklisted zones")
    wf("zones.txt", "\n".join(zones))
    logger.info(f"Got {len(zones)} zones")

    # 3
    a_records = []
    for zone in zones:
        a_records.extend(get_a_records(zone))
    # remove duplicates
    a_records = list(set(a_records))
    # only use internal ips
    tmp = len(a_records)
    a_records = [i for i in a_records if i != "" and ip_address(i).is_private]
    logger.info(f"Removed {tmp - len(a_records)} non private ips")
    # remove blacklisted IPs
    tmp = len(a_records)
    a_records = [i for i in a_records if i not in BLACKLIST_IP]
    logger.info(f"Removed {tmp - len(a_records)} blacklisted ips")
    # remove blacklisted ranges
    tmp = len(a_records)
    for x in BLACKLIST_RANGES:
        net = ip_network(x)
        a_records = [i for i in a_records if ip_address(i) not in net]
    logger.info(f"Removed {tmp - len(a_records)} blacklisted ips from ranges")
    wf("a_records.txt", "\n".join(a_records))
    logger.info(f"Got {len(a_records)} A records")

    # 4
    # https://github.com/nmap/nmap/blob/master/nmap-services
    ports = parse_nmap_services("nmap_services")
    # Blacklisted Ports
    ports = [x for x in ports if x not in BLACKLIST_PORTS]
    logger.info(f"Removed {len(BLACKLIST_PORTS)} blacklisted ports")

    # 5
    start_time = datetime.now()
    logger.info("Starting masscan")
    massscan_output = start_massscan(a_records, ports)

    # 6
    ports = parse_massscan_output(massscan_output)
    logger.info(f"Massscan finished in {calculate_timedelta(start_time)}")

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
    logger.info(f"NMAP scan finished in {calculate_timedelta(start_time)}")

    with open("output.txt", "wb") as f:
        for x in nmap_outputs:
            f.write(x)
    
    # 8
    # order should be preserved on parsing according to JSON docs
    for x in POST_SCAN_SCRIPTS:
        logger.info(execute_process(x).decode('utf-8'))


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
        logger.info(f"script finished in {calculate_timedelta(overall_start_time)}")

