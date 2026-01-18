# backend/services/scanner_service.py
import asyncio
import json
import logging
import socket
import ssl
import re
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import nmap
import requests
import nmap
from zeroconf import Zeroconf, ServiceListener

try:
    from mac_vendor_lookup import MacLookup
except Exception:  # library is optional
    MacLookup = None  # type: ignore

try:
    from scapy.all import ARP, Ether, srp, conf as scapy_conf  # type: ignore
except Exception:  # scapy may be unavailable in runtime
    ARP = Ether = srp = scapy_conf = None  # type: ignore

try:
    from pysnmp.hlapi import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        getCmd,
    )
except Exception:  # SNMP support is optional
    CommunityData = ContextData = ObjectIdentity = ObjectType = None  # type: ignore
    SnmpEngine = UdpTransportTarget = getCmd = None  # type: ignore

logger = logging.getLogger("ScannerService")
logger.setLevel(logging.INFO)

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "data" / "texts.json"
MAC_LOOKUP = None
if MacLookup:
    try:
        MAC_LOOKUP = MacLookup()
        MAC_LOOKUP.load_vendors()
    except Exception:
        MAC_LOOKUP = None


def _safe_decode(b: bytes) -> str:
    try:
        return b.decode(errors="ignore")
    except Exception:
        return repr(b)


def _banner_grab(host: str, port: int, timeout: float = 1.0) -> Optional[str]:
    """TCP banner grab fallback (sync)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                s.sendall(b"\r\n")
            except Exception:
                pass
            try:
                data = s.recv(2048)
                if data:
                    return _safe_decode(data).strip()
            except Exception:
                return None
    except Exception:
        return None
    return None


def arp_scan(timeout: int = 10) -> List[Dict[str, Any]]:
    """
    Использует системную утилиту `arp-scan` (устанавливается в Dockerfile).
    Возвращает список dict: {"ip": "...", "mac": "...", "vendor": "..."}.
    """
    results: List[Dict[str, Any]] = []
    try:
        # -l = локальная подсеть, --localnet можно заменить под конкретный интерфейс
        proc = subprocess.run(
            ["arp-scan", "-l", "--retry=1", "--timeout=200"],
            capture_output=True,
            text=True,
            timeout=timeout + 2,
        )
        out = proc.stdout
        # Строки: "192.168.1.1\taa:bb:cc:dd:ee:ff\tVendor name"
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = re.split(r"\s+", line)
            if len(parts) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                ip = parts[0]
                mac = parts[1]
                vendor = " ".join(parts[2:]) if len(parts) > 2 else None
                # skip header/summary lines
                if (
                    ip.lower().startswith("interface")
                    or "packets" in line.lower()
                ):
                    continue
                results.append({"ip": ip, "mac": mac, "vendor": vendor})
    except FileNotFoundError:
        logger.debug("arp-scan not installed")
    except Exception as e:
        logger.debug("arp_scan failed: %s", e)
    return results


def scapy_arp_scan(network: str, timeout: int = 3) -> List[Dict[str, Any]]:
    """
    Быстрый ARP sweep через scapy (если установлен и есть права на raw sockets).
    Возвращает [{"ip": "...", "mac": "..."}].
    """
    if not (ARP and Ether and srp and scapy_conf):
        return []

    try:
        scapy_conf.verb = 0
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        answered, _ = srp(pkt, timeout=timeout, retry=1)
        results: List[Dict[str, Any]] = []
        for _, recv in answered:
            results.append({"ip": recv.psrc, "mac": recv.hwsrc})
        return results
    except Exception as e:
        logger.debug("scapy ARP failed for %s: %s", network, e)
        return []


def ssdp_probe(timeout: float = 2.0) -> List[Dict[str, Any]]:
    """Multicast M-SEARCH to discover UPnP/SSDP devices on the local network."""
    MCAST_GRP = "239.255.255.250"
    MCAST_PORT = 1900
    msg = "\r\n".join(
        [
            "M-SEARCH * HTTP/1.1",
            f"HOST: {MCAST_GRP}:{MCAST_PORT}",
            'MAN: "ssdp:discover"',
            "MX: 1",
            "ST: ssdp:all",
            "",
            "",
        ]
    ).encode("utf-8")

    results = []
    try:
        sock = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP
        )
        sock.settimeout(timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.sendto(msg, (MCAST_GRP, MCAST_PORT))
        start = datetime.now()
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                txt = _safe_decode(data)
                headers = {}
                for line in txt.split("\r\n"):
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().lower()] = v.strip()
                results.append({"src": addr[0], "headers": headers})
            except socket.timeout:
                break
            if (datetime.now() - start).total_seconds() > timeout + 1:
                break
        sock.close()
    except Exception as e:
        logger.debug("SSDP probe failed: %s", e)
    return results


def mdns_probe(timeout: float = 2.0) -> List[Dict[str, Any]]:
    """
    Простая mDNS / Zeroconf sweep.
    Возвращает records: {"ip": "...", "service": "<name>", "properties": {...}}
    """
    records: List[Dict[str, Any]] = []
    try:
        zer = Zeroconf()
        lock = threading.Event()

        class _Listener(ServiceListener):
            def remove_service(self, zc, type_, name):
                pass

            def add_service(self, zc, type_, name):
                try:
                    info = zc.get_service_info(type_, name, timeout=1000)
                    if info:
                        # IPv4
                        if info.addresses:
                            for addr in info.addresses:
                                ip = socket.inet_ntoa(addr)
                                rec = {
                                    "ip": ip,
                                    "service_name": name,
                                    "type": type_,
                                    "properties": {
                                        (
                                            k.decode()
                                            if isinstance(k, bytes)
                                            else k
                                        ): (
                                            v.decode()
                                            if isinstance(v, bytes)
                                            else v
                                        )
                                        for k, v in (
                                            info.properties or {}
                                        ).items()
                                    },
                                }
                                records.append(rec)
                except Exception:
                    pass

        # Browse common service types, but we can also browse '_services._dns-sd._udp.local.'
        # For speed: browse a selection

        lock.wait(timeout)
        zer.close()
    except Exception as e:
        logger.debug("mdns_probe failed: %s", e)
    return records


async def http_probe(
    host: str, port: int, use_https=False, timeout=3.0
) -> Dict[str, Any]:
    """Try HTTP(S) GET to get server header and <title>."""
    proto = "https" if use_https else "http"
    url = f"{proto}://{host}:{port}/"
    headers = {}
    title = None
    try:
        resp = await asyncio.to_thread(
            requests.get, url, timeout=timeout, allow_redirects=True
        )
        headers = dict(resp.headers)
        m = re.search(
            r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL
        )
        if m:
            title = m.group(1).strip()
    except Exception as e:
        logger.debug("HTTP probe failed %s:%s -> %s", host, port, e)
    return {"headers": headers, "title": title}


async def tls_cert_subject(
    host: str, port: int = 443, timeout: float = 2.0
) -> Optional[str]:
    try:
        loop = asyncio.get_running_loop()

        def _get_cert():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection(
                (host, port), timeout=timeout
            ) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert()
                    subj = cert.get("subject", ())
                    for tup in subj:
                        for k, v in tup:
                            if k == "commonName":
                                return v
                    return str(cert)

        return await loop.run_in_executor(None, _get_cert)
    except Exception:
        return None


def get_vendor_from_local_mac(mac: str) -> Optional[str]:
    if not MAC_LOOKUP:
        return None
    try:
        return MAC_LOOKUP.lookup(mac)
    except Exception:
        return None


def get_vendor_from_api(mac: str, timeout: float = 2.0) -> Optional[str]:
    """
    Простая попытка получить vendor по MAC (через macvendors API).
    Работает только если контейнер/машина подключены в интернет и API доступен.
    """
    try:
        mac_simple = mac.replace(":", "-")
        r = requests.get(
            f"https://api.macvendors.com/{mac_simple}", timeout=timeout
        )
        if r.status_code == 200:
            return r.text.strip()
    except Exception:
        pass
    return None


def _snmp_probe_sync(
    host: str, community: str = "public", timeout: float = 1.0
) -> Optional[Dict[str, Any]]:
    if not (
        SnmpEngine
        and CommunityData
        and ContextData
        and ObjectIdentity
        and ObjectType
        and UdpTransportTarget
        and getCmd
    ):
        return None

    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((host, 161), timeout=int(timeout), retries=0),
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),  # sysDescr
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.5.0")),  # sysName
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.2.0")),  # sysObjectID
        )
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        if errorIndication or errorStatus:
            return None

        mapping = {
            "1.3.6.1.2.1.1.1.0": "sysDescr",
            "1.3.6.1.2.1.1.5.0": "sysName",
            "1.3.6.1.2.1.1.2.0": "sysObjectID",
        }
        data: Dict[str, Any] = {}
        for oid, val in varBinds:
            data[mapping.get(str(oid), str(oid))] = str(val)
        return data
    except Exception as e:
        logger.debug("SNMP probe failed for %s: %s", host, e)
        return None


async def snmp_probe(
    host: str, community: str = "public", timeout: float = 1.0
) -> Optional[Dict[str, Any]]:
    return await asyncio.to_thread(_snmp_probe_sync, host, community, timeout)


class ScannerService:
    def __init__(self) -> None:
        logger.info("ScannerService initialized")
        self.texts = {}
        try:
            with open(DATA_PATH, "r", encoding="utf-8") as f:
                self.texts = json.load(f).get("vulnerabilities", {})
        except Exception:
            logger.debug("No texts.json found or failed to load")

    async def _nmap_discover(self, network: str) -> List[str]:
        loop = asyncio.get_running_loop()
        scanner = nmap.PortScanner()
        await loop.run_in_executor(
            None,
            lambda: scanner.scan(
                hosts=network,
                arguments="-sn -T4 --host-timeout 10s",
            ),
        )
        return scanner.all_hosts()

    async def scan_network(
        self, network: str, concurrency: int = 40
    ) -> List[Dict[str, Any]]:
        logger.info("Starting discovery for %s", network)
        nmap_hosts: List[str] = []
        try:
            nmap_hosts = await self._nmap_discover(network)
        except Exception as e:
            logger.exception("Discovery nmap failed: %s", e)

        # ARP scan (fast, gives MAC + vendor)
        arp_results = await asyncio.to_thread(arp_scan)
        scapy_results = await asyncio.to_thread(scapy_arp_scan, network)
        arp_map = {r["ip"]: r for r in arp_results}

        for r in scapy_results:
            ip = r.get("ip")
            mac = r.get("mac")
            if not ip:
                continue
            vendor_local = get_vendor_from_local_mac(mac) if mac else None
            existing = arp_map.get(ip)
            if existing:
                if mac and not existing.get("mac"):
                    existing["mac"] = mac
                if vendor_local and not existing.get("vendor"):
                    existing["vendor"] = vendor_local
            else:
                arp_map[ip] = {"ip": ip, "mac": mac, "vendor": vendor_local}

        # SSDP + mDNS
        ssdp_results = await asyncio.to_thread(ssdp_probe)
        mdns_results = await asyncio.to_thread(mdns_probe)

        ssdp_map = {}
        for r in ssdp_results:
            ip = r.get("src")
            ssdp_map.setdefault(ip, []).append(r.get("headers"))

        mdns_map = {}
        for r in mdns_results:
            ip = r.get("ip")
            mdns_map.setdefault(ip, []).append(
                {
                    "service_name": r.get("service_name"),
                    "properties": r.get("properties"),
                }
            )

        hosts_set = set(nmap_hosts) | set(arp_map.keys())
        if not hosts_set:
            logger.warning(
                "Discovery returned no hosts. Check network range and container network mode."
            )
            return []

        sem = asyncio.Semaphore(concurrency)

        async def _work(h):
            async with sem:
                return await self._detailed_scan_host(
                    h,
                    ssdp_headers=ssdp_map.get(h),
                    mdns_records=mdns_map.get(h),
                    arp_info=arp_map.get(h),
                )

        tasks = [asyncio.create_task(_work(h)) for h in hosts_set]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        devices = []
        for r in results:
            if isinstance(r, Exception):
                logger.exception("Host scan failed: %s", r)
            elif r:
                devices.append(r)
        logger.info("Network scan finished, devices: %d", len(devices))
        return devices

    async def _detailed_scan_host(
        self,
        host: str,
        ssdp_headers: Optional[List[Dict[str, Any]]] = None,
        mdns_records: Optional[List[Dict[str, Any]]] = None,
        arp_info: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        logger.info("Detailed scan start: %s", host)
        loop = asyncio.get_running_loop()

        nm_args = (
            "-sS -sV -O -p 1-1024 -T4 "
            "--script=banner,http-title -Pn --host-timeout 5s"
        )
        try:
            nm = nmap.PortScanner()
            await loop.run_in_executor(
                None, lambda: nm.scan(hosts=host, arguments=nm_args)
            )
            if host in nm.all_hosts():
                info = nm[host]
        except Exception as e:
            logger.debug("nmap heavy scan failed for %s: %s", host, e)

        snmp_info = await snmp_probe(host)

        addresses = info.get("addresses", {}) if info else {}
        mac = addresses.get("mac") or (
            arp_info.get("mac") if arp_info else None
        )
        vendor = arp_info.get("vendor") if arp_info else None

        hostnames = info.get("hostnames", []) if info else []
        hostname = hostnames[0].get("name") if hostnames else None
        if not hostname and snmp_info and snmp_info.get("sysName"):
            hostname = snmp_info.get("sysName")

        osmatches = info.get("osmatch", []) if info else []
        os_name = osmatches[0].get("name") if osmatches else None
        if not os_name and snmp_info and snmp_info.get("sysDescr"):
            os_name = snmp_info.get("sysDescr")

        tcp = info.get("tcp", {}) if info else {}
        open_ports = []
        http_candidate_ports = {80, 443, 8080, 8000, 8443, 8888, 9443}

        for port, pdata in tcp.items():
            try:
                if pdata.get("state") != "open":
                    continue
                service = pdata.get("name")
                product = pdata.get("product") or pdata.get("extrainfo") or ""
                version = pdata.get("version") or ""
                script = pdata.get("script") or {}
                banner = None

                if script:
                    try:
                        banner = " | ".join(
                            f"{k}: {v}"
                            for k, v in script.items()
                            if isinstance(v, (str, int))
                        )
                    except Exception:
                        banner = str(script)

                if not banner:
                    try:
                        banner = await loop.run_in_executor(
                            None, _banner_grab, host, int(port), 1.0
                        )
                    except Exception:
                        banner = None

                http_info: Dict[str, Any] = {}
                if (
                    service and service.lower() in {"http", "http-proxy"}
                ) or int(port) in http_candidate_ports:
                    use_https = int(port) in {443, 8443, 9443}
                    http_info = await http_probe(
                        host, int(port), use_https=use_https, timeout=3.0
                    )
                    if not banner:
                        if http_info.get("title"):
                            banner = f"HTTP title: {http_info['title']}"
                        elif http_info.get("headers", {}).get("server"):
                            banner = (
                                f"Server: {http_info['headers'].get('server')}"
                            )

                open_ports.append(
                    {
                        "port": int(port),
                        "service": service,
                        "product": product,
                        "version": version,
                        "banner": banner,
                        "http": http_info,
                    }
                )
            except Exception as e:
                logger.debug("Port parse failed %s:%s -> %s", host, port, e)

        cert_subj = None
        if any(p["port"] in {443, 8443, 9443} for p in open_ports):
            https_port = next(
                (
                    p["port"]
                    for p in open_ports
                    if p["port"] in {443, 8443, 9443}
                ),
                443,
            )
            cert_subj = await tls_cert_subject(host, https_port, timeout=2.0)

        if mac and not vendor:
            vendor = get_vendor_from_local_mac(mac) or vendor
        if mac and not vendor:
            try:
                vendor = await asyncio.to_thread(get_vendor_from_api, mac)
            except Exception:
                vendor = None

        device_type = self._detect_device_type_from_ports(open_ports)
        if snmp_info and device_type == "Unknown":
            descr = snmp_info.get("sysDescr", "").lower()
            if "printer" in descr:
                device_type = "Printer"
            elif "camera" in descr:
                device_type = "Camera/IP Camera"

        ssdp_info = ssdp_headers or []
        mdns_info = mdns_records or []

        result = {
            "ip_address": host,
            "mac_address": mac,
            "hostname": hostname,
            "device_type": device_type,
            "manufacturer": vendor,
            "open_ports": open_ports,
            "os": os_name,
            "ssdp": ssdp_info,
            "mdns": mdns_info,
            "tls_subject": cert_subj,
            "snmp": snmp_info,
        }

        logger.info(
            "Scan result for %s: ports=%d os=%s hostname=%s",
            host,
            len(open_ports),
            os_name,
            hostname or "",
        )
        return result

    def _detect_device_type_from_ports(
        self, ports: List[Dict[str, Any]]
    ) -> str:
        if not ports:
            return "Unknown"
        services = {(p.get("service") or "").lower() for p in ports}
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
