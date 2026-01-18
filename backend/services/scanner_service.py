# backend/services/scanner_service.py
import asyncio
import json
import logging
import socket
import ssl
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import nmap  # python-nmap
import requests

logger = logging.getLogger("ScannerService")
logger.setLevel(logging.INFO)

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "data" / "texts.json"


def _safe_decode(b: bytes) -> str:
    try:
        return b.decode(errors="ignore")
    except Exception:
        return repr(b)


def _banner_grab(host: str, port: int, timeout: float = 1.0) -> Optional[str]:
    """
    Простая синхронная banner-grab попытка через tcp socket.
    Используется как fallback, если nmap не вернул подробности.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                # небольшая попытка попросить баннер
                s.sendall(b"\r\n")
            except Exception:
                pass
            try:
                data = s.recv(1024)
                if data:
                    return data.decode(errors="ignore").strip()
            except Exception:
                return None
    except Exception:
        return None
    return None


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
        # загружаем тексты если нужны
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
        self, network: str, concurrency: int = 30
    ) -> List[Dict[str, Any]]:
        logger.info("Starting discovery for %s", network)
        loop = asyncio.get_running_loop()

        try:
            await loop.run_in_executor(
                None,
                lambda: self.nm.scan(
                    hosts=network, arguments="-sn -T4 --host-timeout 10s"
                ),
            )
        except Exception as e:
            logger.exception("Discovery nmap failed: %s", e)
            return []

        hosts = self.nm.all_hosts()
        logger.info("Discovery hosts: %s", hosts)

        ssdp_results = await asyncio.to_thread(ssdp_probe)
        if ssdp_results:
            logger.info("SSDP results: %d", len(ssdp_results))
        ssdp_map = {}
        for r in ssdp_results:
            ip = r.get("src")
            ssdp_map.setdefault(ip, []).append(r.get("headers"))

        sem = asyncio.Semaphore(concurrency)

        async def _scan_host_safe(h: str) -> Optional[Dict[str, Any]]:
            async with sem:
                return await self._detailed_scan_host(h, ssdp_map.get(h))

        tasks = [asyncio.create_task(_work(h)) for h in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        devices: List[Dict[str, Any]] = []
        for r in results:
            if isinstance(r, Exception):
                logger.exception("Host scan failed: %s", r)
            elif r:
                devices.append(r)

        logger.info("Network scan completed, devices found: %d", len(devices))
        return devices

    async def _detailed_scan_host(
        self, host: str, ssdp_headers: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[Dict[str, Any]]:
        logger.info("Detailed scan start: %s", host)
        loop = asyncio.get_running_loop()

        nm_args = "-sS -sV -O -p 1-1024 -T4 --script=banner,http-title -Pn --host-timeout 5s"
        try:
            nm = nmap.PortScanner()
            await loop.run_in_executor(
                None, lambda: self.nm.scan(hosts=host, arguments=nm_args)
            )
            if host in nm.all_hosts():
                info = nm[host]
        except Exception as e:
            logger.exception("nmap heavy scan failed for %s: %s", host, e)
            return None

        try:
            info = self.nm[host]
        except Exception:
            logger.debug("No nmap info for %s", host)
            return None

        addresses = info.get("addresses", {}) or {}
        mac = addresses.get("mac")
        hostnames = info.get("hostnames", []) or []
        hostname = hostnames[0].get("name") if hostnames else None
        osmatches = info.get("osmatch", []) or []
        os_name = osmatches[0].get("name") if osmatches else None
        if not os_name and snmp_info and snmp_info.get("sysDescr"):
            os_name = snmp_info.get("sysDescr")

        tcp = info.get("tcp", {}) or {}
        open_ports = []
        for port, pdata in tcp.items():
            try:
                state = pdata.get("state")
                if state != "open":
                    continue
                service = pdata.get("name")
                product = pdata.get("product") or pdata.get("extrainfo") or ""
                version = pdata.get("version") or ""
                script = pdata.get("script") or {}
                banner = None

            # пробуем взять баннер из nmap script output если есть
            if script:
                # разные скрипты возвращают разные структуры; собираем строково
                try:
                    banner = " | ".join(
                        f"{k}: {v}"
                        for k, v in script.items()
                        if isinstance(v, (str, int))
                    )
                except Exception:
                    banner = str(script)

            # fallback: простая баннер-граб попытка
            if not banner:
                try:
                    banner = await loop.run_in_executor(
                        None, _banner_grab, ip, int(port), 1.0
                    )
                except Exception:
                    banner = None

                http_info = {}
                if (
                    service and service.lower() in {"http", "http-proxy"}
                ) or int(port) in {80, 8080, 8000, 443}:
                    use_https = int(port) in {443, 8443}
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
        if any(p["port"] == 443 for p in open_ports):
            cert_subj = await tls_cert_subject(host, 443, timeout=2.0)

        device_type = self._detect_device_type_from_ports(open_ports)
        ssdp_info = ssdp_headers or []

        result = {
            "ip_address": ip,
            "mac_address": mac,
            "hostname": hostname,
            "device_type": device_type,
            "manufacturer": vendor,
            "open_ports": open_ports,
            "os": os_name,
            "ssdp": ssdp_info,
            "tls_subject": cert_subj,
        }

        logger.info(
            "Scan result for %s: ports=%d os=%s hostname=%s",
            ip,
            len(open_ports),
            os_name,
            hostname,
        )
        return result

    def _detect_device_type_from_ports(
        self, ports: List[Dict[str, Any]]
    ) -> str:
        """Простая эвристика определения типа устройства по сервисам"""
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
