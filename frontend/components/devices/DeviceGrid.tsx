import React from "react";
import { Device } from "@/types";
import { DeviceCard } from "./DeviceCard";

interface DeviceGridProps {
	devices: Device[];
}

export const DeviceGrid: React.FC<DeviceGridProps> = ({ devices }) => {
	return (
		<div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
			{devices.map((device) => (
				<DeviceCard key={device.id} device={device} />
			))}
		</div>
	);
};

