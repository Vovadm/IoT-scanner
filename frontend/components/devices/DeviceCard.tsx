import React from "react";
import Link from "next/link";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Device } from "@/types";

interface DeviceCardProps {
	device: Device;
}

export const DeviceCard: React.FC<DeviceCardProps> = ({ device }) => {
	return (
		<Link href={`/devices/${device.id}`}>
			<Card className="hover:shadow-lg transition-shadow cursor-pointer h-full">
				<CardHeader>
					<div className="flex items-start justify-between">
						<div className="flex-1">
							<CardTitle className="mb-1">
								{device.hostname || device.ip_address}
							</CardTitle>
							<CardDescription>
								{device.ip_address}
							</CardDescription>
						</div>
						<Badge variant="outline">
							{device.device_type || "Unknown"}
						</Badge>
					</div>
				</CardHeader>
				<CardContent>
					<div className="space-y-2 text-sm">
						{device.mac_address && (
							<div>
								<span className="text-muted-foreground">
									MAC:{" "}
								</span>
								<span className="font-mono">
									{device.mac_address}
								</span>
							</div>
						)}
						{device.manufacturer && (
							<div>
								<span className="text-muted-foreground">
									Производитель:{" "}
								</span>
								<span>{device.manufacturer}</span>
							</div>
						)}
						{device.model && (
							<div>
								<span className="text-muted-foreground">
									Модель:{" "}
								</span>
								<span>{device.model}</span>
							</div>
						)}
						{device.operating_system && (
							<div>
								<span className="text-muted-foreground">
									ОС:{" "}
								</span>
								<span>{device.operating_system}</span>
							</div>
						)}
						<div className="pt-2 border-t">
							<span className="text-muted-foreground">
								Последний раз видели:{" "}
							</span>
							<span>
								{new Date(device.last_seen).toLocaleString(
									"ru-RU"
								)}
							</span>
						</div>
					</div>
				</CardContent>
			</Card>
		</Link>
	);
};

