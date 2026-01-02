import React from "react";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Scan } from "@/types";
import { ScanStatus } from "@/types/enums";
import { SCAN_STATUS_VARIANTS, SCAN_STATUS_TEXTS } from "@/utils/constants";

interface ScanListProps {
	scans: Scan[];
	maxItems?: number;
}

export const ScanList: React.FC<ScanListProps> = ({ scans, maxItems = 5 }) => {
	const displayedScans = scans.slice(0, maxItems);

	return (
		<Card>
			<CardHeader>
				<CardTitle>Последние сканирования</CardTitle>
				<CardDescription>
					История выполненных сканирований сети
				</CardDescription>
			</CardHeader>
			<CardContent>
				<div className="space-y-3">
					{displayedScans.length > 0 ? (
						displayedScans.map((scan) => {
							const statusVariant =
								SCAN_STATUS_VARIANTS[
									scan.status as ScanStatus
								] || "secondary";
							const statusText =
								SCAN_STATUS_TEXTS[scan.status as ScanStatus] ||
								scan.status;

							return (
								<div
									key={scan.id}
									className="flex items-center justify-between p-3 border rounded-lg hover:bg-accent transition-colors"
								>
									<div className="flex-1">
										<div className="font-medium">
											{scan.name || scan.target_network}
										</div>
										<div className="text-sm text-muted-foreground">
											{scan.target_network} •{" "}
											{scan.devices_found} устройств
										</div>
									</div>
									<Badge variant={statusVariant}>
										{statusText}
									</Badge>
								</div>
							);
						})
					) : (
						<p className="text-sm text-muted-foreground text-center py-4">
							Нет выполненных сканирований
						</p>
					)}
				</div>
			</CardContent>
		</Card>
	);
};

