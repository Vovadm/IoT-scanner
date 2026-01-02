"use client";

import { useEffect } from "react";
import { PageLayout } from "@/components/common/PageLayout";
import { PageHeader } from "@/components/common/PageHeader";
import { ErrorAlert } from "@/components/common/ErrorAlert";
import { StatsCard } from "@/components/common/StatsCard";
import { ScanForm } from "@/components/scans/ScanForm";
import { ScanList } from "@/components/scans/ScanList";
import { DeviceList } from "@/components/devices/DeviceList";
import { useDevices } from "@/hooks/useDevices";
import { useScans } from "@/hooks/useScans";
import { useScan } from "@/hooks/useScan";
import { Search, Wifi, Shield } from "lucide-react";
import { ScanCreateData } from "@/types";

export default function Home() {
	const { devices, refresh: refreshDevices } = useDevices();
	const { scans, refresh: refreshScans } = useScans();
	const { isScanning, error, startScan } = useScan(() => {
		refreshDevices();
		refreshScans();
	});

	const handleScan = async (data: ScanCreateData) => {
		await startScan(data);
	};

	const completedScans = scans.filter((s) => s.status === "completed").length;
	const runningScans = scans.filter((s) => s.status === "running").length;

	return (
		<PageLayout>
			<PageHeader
				title="IoT Scanner"
				description="Система безопасности для обнаружения и анализа уязвимостей IoT устройств"
			/>

			<ErrorAlert message={error || ""} />

			<div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4 mb-8">
				<StatsCard
					title="Всего устройств"
					value={devices.length}
					icon={Wifi}
				/>
				<StatsCard
					title="Всего сканирований"
					value={scans.length}
					icon={Search}
				/>
				<StatsCard
					title="Завершено"
					value={completedScans}
					icon={Shield}
				/>
				<StatsCard
					title="Выполняется"
					value={runningScans}
					icon={Search}
				/>
			</div>

			<div className="grid gap-6 md:grid-cols-2">
				<ScanForm onSubmit={handleScan} isLoading={isScanning} />
				<ScanList scans={scans} />
			</div>

			<div className="mt-6">
				<DeviceList devices={devices} />
			</div>
		</PageLayout>
	);
}
