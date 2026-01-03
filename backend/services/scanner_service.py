# backend/services/scanner_service.py
import asyncio
import json
import logging
import socket
from pathlib import Path
from typing import Any, Dict, List, Optional

import nmap  # python-nmap

logger = logging.getLogger("ScannerService")
logger.setLevel(logging.INFO)

DATA_PATH = Path(__file__).parent.parent / "data" / "texts.json"


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


class ScannerService:
    def __init__(self) -> None:
        self.nm = nmap.PortScanner()
        logger.info("ScannerService initialized")
        # загружаем тексты если нужны
        self.texts = {}
        try:
            with open(DATA_PATH, "r", encoding="utf-8") as f:
                self.texts = json.load(f).get("vulnerabilities", {})
        except Exception:
            logger.debug("No texts.json found or failed to load")

    async def scan_network(
        self, network: str, concurrency: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Сначала делаем быстрый discovery (-sn), потом для каждого up-host запускаем детальный скан.
        concurrency — число параллельных детальных сканов.
        """
        logger.info("Starting network discovery scan: %s", network)

        # discovery (ping)
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: self.nm.scan(
                hosts=network, arguments="-sn -T4 --host-timeout 10s"
            ),
        )

        hosts = self.nm.all_hosts()
        logger.info("Hosts discovered: %s", hosts)

        # sem для ограничения параллелизма
        sem = asyncio.Semaphore(concurrency)

        async def _scan_host_safe(h: str) -> Optional[Dict[str, Any]]:
            async with sem:
                return await self._detailed_scan_host(h)

        tasks = [asyncio.create_task(_scan_host_safe(h)) for h in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        devices: List[Dict[str, Any]] = []
        for r in results:
            if isinstance(r, Exception):
                logger.exception("Host scan failed: %s", r)
            elif r:
                devices.append(r)

        logger.info("Network scan completed, devices found: %d", len(devices))
        return devices

    async def _detailed_scan_host(self, host: str) -> Optional[Dict[str, Any]]:
        """
        Детальный синхронный nmap-скан для одного хоста — запускаем в executor.
        Возвращаем структуру с ip, mac, hostname, device_type, open_ports (list of dicts).
        """
        logger.info("Detailed scan for %s", host)
        loop = asyncio.get_running_loop()

        # nmap arguments:
        # -sS : TCP SYN (нужны привилегии)
        # -sV : version detection
        # -O  : OS detection (нужны привилегии)
        # -p 1-1024 : порты для сканирования (подберите под свои нужды)
        # -T4 : скорость
        # --script=banner,http-title : NSE скрипты спросить баннер / http title
        # -Pn : не пингуем отдельно (т.к. мы уже знаем что хост up)
        nm_args = "-sS -sV -O -p 1-1024 -T4 --script=banner,http-title -Pn --host-timeout 30s"

        try:
            await loop.run_in_executor(
                None,
                lambda: self.nm.scan(hosts=host, arguments=nm_args),
            )
        except Exception as e:
            logger.exception("nmap scan failed for %s: %s", host, e)
            return None

        try:
            info = self.nm[host]
        except Exception:
            logger.debug("No nmap info for host %s", host)
            return None

        # базовая информация
        ip = host
        addresses = info.get("addresses", {}) or {}
        mac = addresses.get("mac")
        hostnames = info.get("hostnames", []) or []
        hostname = hostnames[0].get("name") if hostnames else None

        # OS detection (nmap может вернуть список os matches)
        osmatches = info.get("osmatch", []) or []
        os_name = osmatches[0].get("name") if osmatches else None

        # собираем порты
        open_ports: List[Dict[str, Any]] = []
        tcp = info.get("tcp", {}) or {}
        for port, pdata in tcp.items():
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

            open_ports.append(
                {
                    "port": int(port),
                    "service": service,
                    "product": product,
                    "version": version,
                    "banner": banner,
                }
            )

        device_type = self._detect_device_type_from_ports(open_ports)

        result = {
            "ip_address": ip,
            "mac_address": mac,
            "hostname": hostname,
            "device_type": device_type,
            "open_ports": open_ports,
            "os": os_name,
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
