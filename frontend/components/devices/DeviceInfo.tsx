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
				{device.manufacturer && (
					<div>
						<span className="text-sm font-medium text-muted-foreground">
							Производитель:
						</span>
						<p>{device.manufacturer}</p>
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
				{device.operating_system && (
					<div>
						<span className="text-sm font-medium text-muted-foreground">
							ОС:
						</span>
						<p>{device.operating_system}</p>
					</div>
				)}
				<div>
					<span className="text-sm font-medium text-muted-foreground">
						Последний раз видели:
					</span>
					<p>{new Date(device.last_seen).toLocaleString("ru-RU")}</p>
				</div>
			</CardContent>
		</Card>
	);
};

