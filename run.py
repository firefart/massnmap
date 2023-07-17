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
import smtplib
import ssl
import socket
from email.message import EmailMessage

VERSION = "1.1"
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


class Scan:
    def __init__(self, config_file):
        p = Path(config_file)
        if not p.is_file():
            logger.error("%s is no valid file", config_file)
            sys.exit(1)
        with p.open(mode="r", encoding="utf-8") as f:
            try:
                config = json.load(f)
            except json.decoder.JSONDecodeError as e:
                logger.error("Invalid config file: %s", e)
                sys.exit(1)

        self.root_zones = config["root_zones"]
        self.blacklist_zones = config["blacklisted_zones"]
        self.blacklist_ip = config["blacklisted_ips"]
        self.blacklist_ports = config["blacklisted_ports"]
        self.blacklist_ranges = config["blacklisted_ranges"]
        self.dns_server = config["dns_server"]
        self.user_agent = config["user_agent"]
        self.post_scan_scripts = config["post_scan_scripts"]
        self.result_dir = config["result_dir"]
        self.massscan_rate = config["massscan_rate"]
        # Mail config
        self.mail_from = config["mail"]["from"]
        self.mail_to = config["mail"]["to"]
        self.mail_server = config["mail"]["server"]
        self.mail_port = config["mail"]["port"]
        self.mail_username = config["mail"]["username"]
        self.mail_password = config["mail"]["password"]
        self.mail_tlsmode = config["mail"]["tlsmode"]
        # create results directory
        if not os.path.exists(self.result_dir):
            os.makedirs(self.result_dir)

    def send_email(self, time_taken):
        if self.mail_server == "":
            return

        hostname = socket.gethostname()
        message = f"massnmap finished on {hostname} in {time_taken}"
        msg = EmailMessage()
        msg['Subject'] = message
        msg['From'] = self.mail_from
        msg['To'] = self.mail_to
        msg.set_content(message)

        if self.mail_tlsmode == "off":
            with smtplib.SMTP(self.mail_server, self.mail_port) as server:
                if self.mail_username != "" and self.mail_password != "":
                    server.login(self.mail_username, self.mail_password)
                server.send_message(msg)
        elif self.mail_tlsmode == "on":
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(self.mail_server, self.mail_port, context=context) as server:
                if self.mail_username != "" and self.mail_password != "":
                    server.login(self.mail_username, self.mail_password)
                server.send_message(msg)
        elif self.mail_tlsmode == "starttls":
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(self.mail_server, self.mail_port, context=context) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                if self.mail_username != "" and self.mail_password != "":
                    server.login(self.mail_username, self.mail_password)
                server.send_message(msg)
        else:
            raise ValueError(f"invalid tls mode {self.mail_tlsmode}")

    def __parse_massscan_output(self, output):
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

    def __generate_massscan_config(self, ports_to_scan, file_in, file_out):
        ports = ",".join(ports_to_scan)
        return (
            f"rate = {self.massscan_rate}.00\n"
            "randomize-hosts = true\n"
            "show = open\n"
            f"ports = {ports}\n"
            f"includefile = {file_in}\n"
            "output-format = list\n"
            f"output-filename = {file_out}\n"
        )

    def __parse_nmap_services(self, filename):
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

    def __execute_process(self, c, shell=False):
        logger.debug("Executing %s", c)
        # Needed when shell = False
        if not shell and isinstance(c, str):
            c = c.split()
        try:
            output = subprocess.check_output(c, stderr=subprocess.STDOUT, shell=shell)
        except subprocess.CalledProcessError as e:
            logger.error("Error when running %s: %s", c, e.output)
            output = e.output
        return output

    def __get_zones(self):
        zones = []
        for root_zone in self.root_zones:
            a = self.__execute_process(f"dig @{self.dns_server} -t axfr {root_zone} | grep -E \"\s+NS\s+\" | awk '{{print $1}}' | sort -u | sed -r \"s/\.$//\"", True) # pylint: disable=anomalous-backslash-in-string
            x = a.strip().split(b"\n")
            zones.extend([y.decode("utf-8") for y in x])
        return zones

    def __get_a_records(self, zone):
        zone = zone if isinstance(zone, str) else zone.decode('utf-8')
        a = self.__execute_process(f"dig @{self.dns_server} -t axfr {zone} | grep -E \"\s+A\s+\" | awk '{{print $5}}' | sort -V", True) # pylint: disable=anomalous-backslash-in-string
        x = a.strip().split(b"\n")
        return [y.decode("utf-8") for y in x]

    def __start_massscan(self, records, ports):
        with tempfile.NamedTemporaryFile() as input_file, tempfile.NamedTemporaryFile() as output_file, tempfile.NamedTemporaryFile() as config_file:
            for r in records:
                line = f"{r.strip()}\n".encode("utf-8")
                input_file.write(line)
            input_file.flush()

            config = self.__generate_massscan_config(ports, input_file.name, output_file.name)
            config_file.write(config.encode("utf-8"))
            config_file.flush()

            self.__execute_process(["masscan", "-c", config_file.name])
            output_file.flush()
            output_file.seek(0)
            output = output_file.read()
        return output

    # no __ here or imap_unordered can not call this method
    def _start_nmaps(self, item):
        start_time = datetime.now()
        ip = item[0]
        ports = item[1]
        if len(ports) == 0:
            logger.debug("No open ports for %s", ip)
            return ""
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
                logger.error("Unknown protocol %s", p.protocol)
            portmapping += str(p.port)
            portmapping += ","
        portmapping = portmapping.rstrip(",")

        scan_type = "-s"
        scan_type += ("S" if uses_tcp else "")
        scan_type += ("U" if uses_udp else "")
        scan_type += "V"  # version detection
        with tempfile.NamedTemporaryFile() as output_file:
            nmap_command = [
                "nmap", "-p", portmapping,
                scan_type,
                "-Pn",
                "-T5",
                "-O",
                "-A",
                "--osscan-guess",
                "--host-timeout", "10m",
                "-oN", output_file.name,
                "-oX", f"{self.result_dir}/{ip}.xml",
                "--dns-servers", self.dns_server,
                "--script-args", f"http.useragent=\"{self.user_agent}\"",
                ip
            ]
            self.__execute_process(nmap_command)
            output_file.flush()
            output_file.seek(0)
            output = output_file.read()
        process_name = current_process().name
        delta = calculate_timedelta(start_time)
        logger.debug("%s finished (%s)", process_name, delta)
        return output

    def scan(self):
        # 1) get zones
        # 2) extract all a records from zones
        # 3) parse nmap_services for top used ports and remove blacklisted ports
        # 4) massscan of a records
        # 5) parse massscan output
        # 6) run single nmap scans with discovered ports
        # 7) run post scan scripts

        # 1
        zones = self.__get_zones()
        # also append root zone (also contains A records)
        zones.extend(self.root_zones)
        tmp = len(zones)
        zones = [z for z in zones if z not in self.blacklist_zones]
        logger.info("Removed %d blacklisted zones", tmp - len(zones))
        wf("zones.txt", "\n".join(zones))
        logger.info("Got %d zones", len(zones))

        # 2
        a_records = []
        for zone in zones:
            a_records.extend(self.__get_a_records(zone))
        # remove duplicates
        a_records = list(set(a_records))
        # only use internal ips
        tmp = len(a_records)
        a_records = [i for i in a_records if i != "" and ip_address(i).is_private]
        logger.info("Removed %d non private ips", tmp - len(a_records))
        # remove blacklisted IPs
        tmp = len(a_records)
        a_records = [i for i in a_records if i not in self.blacklist_ip]
        logger.info("Removed %d blacklisted ips", tmp - len(a_records))
        # remove blacklisted ranges
        tmp = len(a_records)
        for x in self.blacklist_ranges:
            net = ip_network(x)
            a_records = [i for i in a_records if ip_address(i) not in net]
        logger.info("Removed %d blacklisted ips from ranges", tmp - len(a_records))
        wf("a_records.txt", "\n".join(a_records))
        logger.info("Got %d A records", len(a_records))

        # 3
        # https://github.com/nmap/nmap/blob/master/nmap-services
        ports = self.__parse_nmap_services("nmap_services")
        # Blacklisted Ports
        ports = [x for x in ports if x not in self.blacklist_ports]
        logger.info("Removed %d blacklisted ports", len(self.blacklist_ports))

        # 4
        start_time = datetime.now()
        logger.info("Starting masscan with rate %s", self.massscan_rate)
        massscan_output = self.__start_massscan(a_records, ports)

        # 5
        ports = self.__parse_massscan_output(massscan_output)
        logger.info("Massscan finished in %s", calculate_timedelta(start_time))

        # 6
        start_time = datetime.now()
        logger.info("Starting nmap armada")
        nmap_outputs = []
        with Pool(NUM_WORKERS) as pool:
            ips_to_scan = len(ports)
            for counter, output in enumerate(pool.imap_unordered(self._start_nmaps, ports.items()), 1):
                nmap_outputs.append(output)
                done_percent = counter/ips_to_scan
                text = f"Nmap progress: {done_percent:.2%} ({counter}/{ips_to_scan})"
                if sys.stderr.isatty():
                    # progressbar style when there is a tty attached
                    text = f"\r{text}"
                    sys.stderr.write(text)
                elif (counter % 100 == 0) or (counter == ips_to_scan):
                    # when writing to the logs only report every 100 scans or on the last item
                    text = f"{text}\n"
                    sys.stderr.write(text)
                    sys.stderr.flush()
            sys.stderr.write("\n")
        logger.info("NMAP scan finished in %s", calculate_timedelta(start_time))

        with open("output.txt", "wb", encoding="utf-8") as f:
            for x in nmap_outputs:
                f.write(x)

        # 7
        # order should be preserved on parsing according to JSON docs
        for x in self.post_scan_scripts:
            logger.info("starting post scan script %s", x)
            script_start_time = datetime.now()
            logger.info(self.__execute_process(x).decode('utf-8'))
            logger.info("%s finished in %s", x, calculate_timedelta(script_start_time))


def wf(fname, content):
    with open(fname, "wt", encoding="utf-8") as f:
        f.write(content)


def rf(fname):
    with open(fname, "rt", encoding="utf-8") as f:
        return f.read()


def extract_string(r, string):
    m = re.search(r, string)
    if m:
        return m.group(1)
    return ""


def calculate_timedelta(time1):
    now = datetime.now()
    return now - time1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="scan")
    parser.add_argument("-c", "--config", required=True, help="config file to use")
    parser.add_argument("-d", "--debug", action="store_true", help="set loglevel to DEBUG")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    overall_start_time = datetime.now()
    s = Scan(config_file=args.config)
    try:
        s.scan()
    finally:
        overall_time = calculate_timedelta(overall_start_time)
        logger.info("script finished in %s", overall_time)
        s.send_email(overall_time)
