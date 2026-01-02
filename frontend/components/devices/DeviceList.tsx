import React from "react";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import Link from "next/link";
import { Device } from "@/types";
import { DeviceListItem } from "./DeviceListItem";

interface DeviceListProps {
	devices: Device[];
	maxItems?: number;
	showViewAll?: boolean;
}

export const DeviceList: React.FC<DeviceListProps> = ({
	devices,
	maxItems = 5,
	showViewAll = true,
}) => {
	const displayedDevices = devices.slice(0, maxItems);

	return (
		<Card>
			<CardHeader>
				<div className="flex items-center justify-between">
					<div>
						<CardTitle>Обнаруженные устройства</CardTitle>
						<CardDescription>
							Список всех найденных IoT устройств в сети
						</CardDescription>
					</div>
					{showViewAll && (
						<Link href="/devices">
							<Button variant="outline">Посмотреть все</Button>
						</Link>
					)}
				</div>
			</CardHeader>
			<CardContent>
				<div className="space-y-3">
					{displayedDevices.length > 0 ? (
						displayedDevices.map((device) => (
							<DeviceListItem key={device.id} device={device} />
						))
					) : (
						<p className="text-sm text-muted-foreground text-center py-4">
							Устройства не найдены. Запустите сканирование для
							поиска устройств.
						</p>
					)}
				</div>
			</CardContent>
		</Card>
	);
};

