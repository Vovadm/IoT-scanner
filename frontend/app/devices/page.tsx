"use client";

import { PageLayout } from "@/components/common/PageLayout";
import { PageHeader } from "@/components/common/PageHeader";
import { BackButton } from "@/components/common/BackButton";
import { LoadingSpinner } from "@/components/common/LoadingSpinner";
import { ErrorAlert } from "@/components/common/ErrorAlert";
import { DeviceGrid } from "@/components/devices/DeviceGrid";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Wifi } from "lucide-react";
import Link from "next/link";
import { useDevices } from "@/hooks/useDevices";

export default function DevicesPage() {
	const { devices, loading, error } = useDevices();

	return (
		<PageLayout>
			<PageHeader
				title="Устройства"
				description="Список всех обнаруженных IoT устройств"
				backButton={<BackButton href="/" />}
			/>

			<ErrorAlert message={error || ""} />

			{loading ? (
				<LoadingSpinner message="Загрузка устройств..." />
			) : devices.length === 0 ? (
				<Card>
					<CardContent className="py-12 text-center">
						<Wifi className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
						<h3 className="text-lg font-semibold mb-2">
							Устройства не найдены
						</h3>
						<p className="text-muted-foreground mb-4">
							Запустите сканирование сети для обнаружения
							устройств
						</p>
						<Link href="/">
							<Button>Запустить сканирование</Button>
						</Link>
					</CardContent>
				</Card>
			) : (
				<DeviceGrid devices={devices} />
			)}
		</PageLayout>
	);
}
