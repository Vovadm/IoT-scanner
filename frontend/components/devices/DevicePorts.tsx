import React from "react";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { PortInfo } from "@/types";

interface DevicePortsProps {
	ports: PortInfo[];
}

export const DevicePorts: React.FC<DevicePortsProps> = ({ ports }) => {
	return (
		<Card>
			<CardHeader>
				<CardTitle>Открытые порты</CardTitle>
				<CardDescription>
					{ports.length} портов обнаружено
				</CardDescription>
			</CardHeader>
			<CardContent>
				{ports.length > 0 ? (
					<div className="space-y-2">
						{ports.map((port, index) => (
							<div
								key={index}
								className="flex items-center justify-between p-2 border rounded"
							>
								<div>
									<span className="font-mono font-semibold">
										:{port.port}
									</span>
									<span className="ml-2 text-sm text-muted-foreground">
										{port.service}
									</span>
								</div>
								{port.product && (
									<Badge variant="outline">
										{port.product}
									</Badge>
								)}
							</div>
						))}
					</div>
				) : (
					<p className="text-sm text-muted-foreground">
						Открытые порты не обнаружены
					</p>
				)}
			</CardContent>
		</Card>
	);
};

