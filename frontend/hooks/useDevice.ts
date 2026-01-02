import { useState, useEffect, useCallback } from "react";
import { DeviceWithVulnerabilities } from "@/types";
import { getDevice } from "@/lib/api";

interface UseDeviceReturn {
	device: DeviceWithVulnerabilities | null;
	loading: boolean;
	error: string | null;
	refresh: () => Promise<void>;
}

export const useDevice = (deviceId: number): UseDeviceReturn => {
	const [device, setDevice] = useState<DeviceWithVulnerabilities | null>(
		null
	);
	const [loading, setLoading] = useState<boolean>(true);
	const [error, setError] = useState<string | null>(null);

	const fetchDevice = useCallback(async () => {
		if (!deviceId) return;

		try {
			setLoading(true);
			setError(null);
			const data = await getDevice(deviceId);
			setDevice(data);
		} catch (err) {
			const errorMessage =
				err instanceof Error
					? err.message
					: "Ошибка загрузки устройства";
			setError(errorMessage);
			console.error("Error loading device:", err);
		} finally {
			setLoading(false);
		}
	}, [deviceId]);

	useEffect(() => {
		fetchDevice();
	}, [fetchDevice]);

	return {
		device,
		loading,
		error,
		refresh: fetchDevice,
	};
};

