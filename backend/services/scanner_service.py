import json
from pathlib import Path
from typing import List, Dict, Any

import nmap

from models.enums import VulnerabilitySeverity


DATA_PATH = Path(__file__).parent.parent / "data" / "texts.json"


class ScannerService:
    def __init__(self) -> None:
        self.nm = nmap.PortScanner()
        with open(DATA_PATH, "r", encoding="utf-8") as f:
            self.texts = json.load(f)["vulnerabilities"]

    async def scan_network(self, network: str) -> List[Dict[str, Any]]:
        devices: List[Dict[str, Any]] = []

        self.nm.scan(hosts=network, arguments="-sn")

        for host in self.nm.all_hosts():
            if self.nm[host].state() != "up":
                continue

            info: Dict[str, Any] = {
                "ip_address": host,
                "mac_address": self.nm[host].get("addresses", {}).get("mac"),
                "hostname": None,
                "device_type": None,
                "open_ports": [],
            }

            hostnames = self.nm[host].get("hostnames", [])
            if hostnames:
                info["hostname"] = hostnames[0].get("name")

            self.nm.scan(host, arguments="-sV -p 1-1000")

            ports: List[Dict[str, Any]] = []

            for port, data in self.nm[host].get("tcp", {}).items():
                if data.get("state") == "open":
                    ports.append(
                        {
                            "port": port,
                            "service": data.get("name", "unknown"),
                            "version": data.get("version", ""),
                            "product": data.get("product", ""),
                        }
                    )

            info["open_ports"] = ports
            info["device_type"] = self._detect_device_type(ports)

            devices.append(info)

        return devices

    def _detect_device_type(self, ports: List[Dict[str, Any]]) -> str:
        if not ports:
            return "Unknown"

        services = {p["service"].lower() for p in ports}

        if services & {"rtsp", "onvif"}:
            return "Camera/IP Camera"
        if services & {"telnet", "ssh", "http"}:
            return "Router/Network Device"
        if services & {"ipp", "lpd"}:
            return "Printer"
        if services & {"upnp", "ssdp"}:
            return "Smart Device/IoT"
        if services & {"ssh", "ftp", "smb"}:
            return "Server"

        return "IoT Device"

    async def scan_device_vulnerabilities(
        self,
        device_data: Dict[str, Any],
        ports_data: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        vulns: List[Dict[str, Any]] = []

        for p in ports_data:
            port = p["port"]
            service = p["service"].lower()

            if service == "telnet" and port == 23:
                vulns.append(
                    self._make(
                        "telnet",
                        VulnerabilitySeverity.HIGH,
                        port,
                        "telnet",
                    )
                )

            if service == "ftp" and port == 21:
                vulns.append(
                    self._make(
                        "ftp",
                        VulnerabilitySeverity.MEDIUM,
                        port,
                        "ftp",
                    )
                )

            if service == "http" and port in {80, 8080, 8000}:
                vulns.append(
                    self._make(
                        "http",
                        VulnerabilitySeverity.MEDIUM,
                        port,
                        "http",
                    )
                )

            if service == "ssh":
                vulns.append(
                    self._make(
                        "ssh",
                        VulnerabilitySeverity.LOW,
                        port,
                        "ssh",
                    )
                )

            if service == "upnp" or port == 1900:
                vulns.append(
                    self._make(
                        "upnp",
                        VulnerabilitySeverity.MEDIUM,
                        port,
                        "upnp",
                    )
                )

            if service in {"smb", "microsoft-ds"} and port in {139, 445}:
                vulns.append(
                    self._make(
                        "smb",
                        VulnerabilitySeverity.HIGH,
                        port,
                        "smb",
                    )
                )

        if len(ports_data) > 10:
            text = self.texts["many_ports"]
            vulns.append(
                {
                    "title": text["title"],
                    "description": text["description"].format(
                        count=len(ports_data)
                    ),
                    "severity": VulnerabilitySeverity.MEDIUM,
                    "port": None,
                    "service": None,
                    "recommendation": "\n".join(text["recommendation"]),
                }
            )

        device_type = device_data.get("device_type", "")
        if any(x in device_type for x in {"IoT", "Camera", "Router"}):
            vulns.append(
                self._make(
                    "default_credentials",
                    VulnerabilitySeverity.CRITICAL,
                    None,
                    None,
                )
            )

        return vulns

    def _make(
        self,
        key: str,
        severity: VulnerabilitySeverity,
        port: int | None,
        service: str | None,
    ) -> Dict[str, Any]:
        text = self.texts[key]
        return {
            "title": text["title"],
            "description": text["description"],
            "severity": severity,
            "port": port,
            "service": service,
            "recommendation": "\n".join(text["recommendation"]),
        }
