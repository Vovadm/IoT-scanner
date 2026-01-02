"use client";

import { useEffect } from "react";
import { useParams } from "next/navigation";
import { PageLayout } from "@/components/common/PageLayout";
import { PageHeader } from "@/components/common/PageHeader";
import { BackButton } from "@/components/common/BackButton";
import { LoadingSpinner } from "@/components/common/LoadingSpinner";
import { ErrorAlert } from "@/components/common/ErrorAlert";
import { StatsCard } from "@/components/common/StatsCard";
import { DeviceInfo } from "@/components/devices/DeviceInfo";
import { DevicePorts } from "@/components/devices/DevicePorts";
import { VulnerabilityList } from "@/components/vulnerabilities/VulnerabilityList";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { AlertTriangle, Shield, CheckCircle } from "lucide-react";
import Link from "next/link";
import { useDevice } from "@/hooks/useDevice";
import { VulnerabilitySeverity } from "@/types/enums";
import { PortInfo } from "@/types";

export default function DeviceDetailPage() {
	const params = useParams();
	const deviceId = parseInt(params.id as string);

	const { device, loading, error, refresh } = useDevice(deviceId);

	useEffect(() => {
		if (deviceId) {
			const interval = setInterval(() => {
				refresh();
			}, 5000);
			return () => clearInterval(interval);
		}
	}, [deviceId, refresh]);

	if (loading) {
		return (
			<PageLayout>
				<LoadingSpinner message="Загрузка устройства..." />
			</PageLayout>
		);
	}

	if (error || !device) {
		return (
			<PageLayout>
				<PageHeader
					title="Устройство"
					backButton={
						<BackButton
							href="/devices"
							label="Назад к устройствам"
						/>
					}
				/>
				<ErrorAlert message={error || "Устройство не найдено"} />
				<Card>
					<CardContent className="py-12 text-center">
						<AlertTriangle className="h-12 w-12 mx-auto mb-4 text-destructive" />
						<h3 className="text-lg font-semibold mb-2">
							Устройство не найдено
						</h3>
						<Link href="/devices">
							<Button>Вернуться к списку устройств</Button>
						</Link>
					</CardContent>
				</Card>
			</PageLayout>
		);
	}

	const openPorts: PortInfo[] = device.open_ports
		? JSON.parse(device.open_ports)
		: [];
	const criticalVulns = device.vulnerabilities.filter(
		(v) => v.severity === VulnerabilitySeverity.CRITICAL
	).length;
	const highVulns = device.vulnerabilities.filter(
		(v) => v.severity === VulnerabilitySeverity.HIGH
	).length;
	const fixedVulns = device.vulnerabilities.filter(
		(v) => v.fixed === "true"
	).length;

	return (
		<PageLayout>
			<PageHeader
				title={device.hostname || device.ip_address}
				description={device.device_type || "Неизвестное устройство"}
				backButton={
					<BackButton href="/devices" label="Назад к устройствам" />
				}
			/>

			<div className="grid gap-6 md:grid-cols-3 mb-6">
				<StatsCard
					title="Всего уязвимостей"
					value={device.vulnerabilities.length}
					icon={Shield}
				/>
				<StatsCard
					title="Критичных"
					value={criticalVulns + highVulns}
					icon={AlertTriangle}
					className="text-red-600"
				/>
				<StatsCard
					title="Исправлено"
					value={fixedVulns}
					icon={CheckCircle}
					className="text-green-600"
				/>
			</div>

			<div className="grid gap-6 md:grid-cols-2">
				<DeviceInfo device={device} />
				<DevicePorts ports={openPorts} />
			</div>

			<div className="mt-6">
				<VulnerabilityList
					vulnerabilities={device.vulnerabilities}
					onUpdate={refresh}
				/>
			</div>
		</PageLayout>
	);
}
