import asyncio
import json
import logging
from typing import Any, Dict, List

import nmap

logger = logging.getLogger("ScannerService")


class ScannerService:
    def __init__(self) -> None:
        self.nm = nmap.PortScanner()
        logger.info("ScannerService initialized")

    async def scan_network(self, network: str) -> List[Dict[str, Any]]:
        logger.info("Starting network scan: %s", network)

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: self.nm.scan(
                hosts=network,
                arguments="-sn -T4 --host-timeout 10s",
            ),
        )

        hosts = self.nm.all_hosts()
        logger.info("Hosts discovered: %s", hosts)

        devices: List[Dict[str, Any]] = []

        for host in hosts:
            state = self.nm[host].state()
            logger.debug("Host %s state: %s", host, state)

            if state != "up":
                continue

            device = {
                "ip_address": host,
                "hostname": self._get_hostname(host),
                "open_ports": json.dumps([]),
                "os": None,
            }
            devices.append(device)

        logger.info("Network scan completed, devices found: %d", len(devices))
        return devices

    async def scan_device_vulnerabilities(
        self, device_data: Dict[str, Any], ports: List[int]
    ) -> List[Dict[str, Any]]:
        ip = device_data["ip_address"]
        logger.info("Scanning device %s ports: %s", ip, ports)

        if not ports:
            logger.info(
                "No ports provided for %s, skipping vulnerability scan", ip
            )
            return []

        ports_str = ",".join(map(str, ports))

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: self.nm.scan(
                hosts=ip,
                arguments=f"-sV -p {ports_str} -T4 --host-timeout 20s",
            ),
        )

        vulnerabilities: List[Dict[str, Any]] = []

        for proto in self.nm[ip].all_protocols():
            for port, port_data in self.nm[ip][proto].items():
                service = port_data.get("name")
                product = port_data.get("product")
                version = port_data.get("version")

                vuln = {
                    "title": f"Open port {port}",
                    "description": f"Service {service} {product} {version}",
                    "severity": "medium",
                    "port": port,
                    "service": service,
                    "recommendation": (
                        "Restrict access or close the port if unused"
                    ),
                }

                logger.debug("Vulnerability found on %s:%s", ip, port)
                vulnerabilities.append(vuln)

        logger.info(
            "Vulnerability scan completed for %s, found: %d",
            ip,
            len(vulnerabilities),
        )
        return vulnerabilities

    def _get_hostname(self, host: str) -> str | None:
        try:
            hostnames = self.nm[host].get("hostnames")
            if hostnames:
                return hostnames[0].get("name")
        except Exception:
            pass
        return None
