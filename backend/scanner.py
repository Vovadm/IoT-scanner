import json
from pathlib import Path
from typing import List, Dict, Any

import nmap

from models import Device, VulnerabilitySeverity


TEXTS_PATH = Path(__file__).parent / "data" / "texts.json"


class IoTScanner:
    def __init__(self) -> None:
        self.nm = nmap.PortScanner()
        self.texts = self._load_texts()

    def _load_texts(self) -> Dict[str, Any]:
        with open(TEXTS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)["vulnerabilities"]

    def scan_network(self, network: str) -> List[Dict[str, Any]]:
        devices: List[Dict[str, Any]] = []

        self.nm.scan(hosts=network, arguments="-sn")

        for host in self.nm.all_hosts():
            if self.nm[host].state() != "up":
                continue

            device_info: Dict[str, Any] = {
                "ip_address": host,
                "mac_address": self.nm[host].get("addresses", {}).get("mac"),
                "hostname": (
                    self.nm[host].get("hostnames", [{}])[0].get("name")
                    if self.nm[host].get("hostnames")
                    else None
                ),
                "device_type": None,
                "open_ports": [],
            }

            self.nm.scan(host, arguments="-sV -p 1-1000")

            ports: List[Dict[str, Any]] = []

            for port, info in self.nm[host].get("tcp", {}).items():
                if info.get("state") == "open":
                    ports.append(
                        {
                            "port": port,
                            "service": info.get("name", "unknown"),
                            "version": info.get("version", ""),
                        }
                    )

            device_info["open_ports"] = ports
            device_info["device_type"] = self._detect_device_type(ports)

            devices.append(device_info)

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

    def scan_device_vulnerabilities(
        self, device: Device, ports_data: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        v = self.texts
        vulnerabilities: List[Dict[str, Any]] = []

        for p in ports_data:
            port = p["port"]
            service = p["service"].lower()
            version = p.get("version", "")

            if service == "telnet" and port == 23:
                vulnerabilities.append(
                    self._make_vuln(
                        v["telnet_open"], VulnerabilitySeverity.HIGH, port
                    )
                )

            if service == "ftp" and port == 21:
                vulnerabilities.append(
                    self._make_vuln(
                        v["ftp_open"], VulnerabilitySeverity.MEDIUM, port
                    )
                )

            if service == "http" and port in {80, 8080, 8000}:
                vulnerabilities.append(
                    self._make_vuln(
                        v["http_open"], VulnerabilitySeverity.MEDIUM, port
                    )
                )

            if service == "ssh":
                key = "ssh_outdated" if "1." in version else "ssh_general"
                vulnerabilities.append(
                    self._make_vuln(
                        v[key],
                        (
                            VulnerabilitySeverity.HIGH
                            if key == "ssh_outdated"
                            else VulnerabilitySeverity.LOW
                        ),
                        port,
                        version=version,
                    )
                )

            if service == "upnp" or port == 1900:
                vulnerabilities.append(
                    self._make_vuln(
                        v["upnp"], VulnerabilitySeverity.MEDIUM, port
                    )
                )

            if service in {"smb", "microsoft-ds"} and port in {139, 445}:
                vulnerabilities.append(
                    self._make_vuln(
                        v["smb_open"], VulnerabilitySeverity.HIGH, port
                    )
                )

        if len(ports_data) > 10:
            vulnerabilities.append(
                self._make_vuln(
                    v["many_ports"],
                    VulnerabilitySeverity.MEDIUM,
                    None,
                    count=len(ports_data),
                )
            )

            device_type_value = getattr(device, "device_type", None)

            if device_type_value and any(
                k in device_type_value for k in {"IoT", "Camera", "Router"}
            ):
                vulnerabilities.append(
                    self._make_vuln(
                        v["default_credentials"],
                        VulnerabilitySeverity.CRITICAL,
                        None,
                    )
                )

            vulnerabilities.append(
                self._make_vuln(
                    v["default_credentials"],
                    VulnerabilitySeverity.CRITICAL,
                    None,
                )
            )

        return vulnerabilities

    def _make_vuln(
        self,
        template: Dict[str, Any],
        severity: VulnerabilitySeverity,
        port: int | None,
        **fmt: Any,
    ) -> Dict[str, Any]:
        return {
            "title": template["title"],
            "description": template["description"].format(**fmt),
            "severity": severity,
            "port": port,
            "service": None,
            "recommendation": "\n".join(template["recommendation"]),
        }
