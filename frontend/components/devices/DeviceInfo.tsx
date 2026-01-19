import React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DeviceWithVulnerabilities } from "@/types";

interface DeviceInfoProps {
	device: DeviceWithVulnerabilities;
}

export const DeviceInfo: React.FC<DeviceInfoProps> = ({ device }) => {
	return (
		<Card>
			<CardHeader>
				<CardTitle>Информация об устройстве</CardTitle>
			</CardHeader>
			<CardContent className="space-y-4">
				<div>
					<span className="text-sm font-medium text-muted-foreground">
						IP-адрес:
					</span>
					<p className="font-mono">{device.ip_address}</p>
				</div>
				{device.mac_address && (
					<div>
						<span className="text-sm font-medium text-muted-foreground">
							MAC-адрес:
						</span>
						<p className="font-mono">{device.mac_address}</p>
					</div>
				)}
				{device.hostname && (
					<div>
						<span className="text-sm font-medium text-muted-foreground">
							Имя хоста:
						</span>
						<p>{device.hostname}</p>
					</div>
				)}
				{device.device_type && (
					<div>
						<span className="text-sm font-medium text-muted-foreground">
							Тип устройства:
						</span>
						<p>{device.device_type}</p>
					</div>
				)}
				{(device.vendor || device.manufacturer) && (
					<div>
						<span className="text-sm font-medium text-muted-foreground">
							Производитель:
						</span>
						<p>{device.vendor || device.manufacturer}</p>
					</div>
				)}
				{device.model && (
					<div>
						<span className="text-sm font-medium text-muted-foreground">
							Модель:
						</span>
						<p>{device.model}</p>
					</div>
				)}
				{(device.operating_system || device.os) && (
					<div>
						<span className="text-sm font-medium text-muted-foreground">
							Операционная система:
						</span>
						<p>{device.operating_system || device.os}</p>
					</div>
				)}
				{device.open_ports && Array.isArray(device.open_ports) && device.open_ports.length > 0 && (
					<div>
						<span className="text-sm font-medium text-muted-foreground">
							Открытые порты:
						</span>
						<p className="font-mono">
							{device.open_ports.map(p => `${p.port}/${p.service}`).join(", ")}
						</p>
					</div>
				)}
				<div>
					<span className="text-sm font-medium text-muted-foreground">
						Последний раз видели:
					</span>
					<p>{new Date(device.last_seen).toLocaleString("ru-RU")}</p>
				</div>
				<div>
					<span className="text-sm font-medium text-muted-foreground">
						Добавлено:
					</span>
					<p>{new Date(device.created_at).toLocaleString("ru-RU")}</p>
				</div>
			</CardContent>
		</Card>
	);
};

