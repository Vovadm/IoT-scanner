import React from "react";
import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Device } from "@/types";

interface DeviceListItemProps {
	device: Device;
}

export const DeviceListItem: React.FC<DeviceListItemProps> = ({ device }) => {
	return (
		<Link href={`/devices/${device.id}`}>
			<div className="flex items-center justify-between p-3 border rounded-lg hover:bg-accent transition-colors cursor-pointer">
				<div className="flex-1">
					<div className="font-medium">
						{device.hostname || device.ip_address}
					</div>
					<div className="text-sm text-muted-foreground">
						{device.device_type || "Неизвестное устройство"} •{" "}
						{device.ip_address}
					</div>
				</div>
				<Badge variant="outline">
					{device.device_type || "Unknown"}
				</Badge>
			</div>
		</Link>
	);
};

