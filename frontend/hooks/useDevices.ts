import { useState, useEffect, useCallback } from "react";
import { Device } from "@/types";
import { getDevices } from "@/lib/api";

interface UseDevicesReturn {
	devices: Device[];
	loading: boolean;
	error: string | null;
	refresh: () => Promise<void>;
}

export const useDevices = (): UseDevicesReturn => {
	const [devices, setDevices] = useState<Device[]>([]);
	const [loading, setLoading] = useState<boolean>(true);
	const [error, setError] = useState<string | null>(null);

	const fetchDevices = useCallback(async () => {
		try {
			setLoading(true);
			setError(null);
			const data = await getDevices();
			setDevices(data);
		} catch (err) {
			const errorMessage =
				err instanceof Error
					? err.message
					: "Ошибка загрузки устройств";
			setError(errorMessage);
			console.error("Error loading devices:", err);
		} finally {
			setLoading(false);
		}
	}, []);

	useEffect(() => {
		fetchDevices();
	}, [fetchDevices]);

	return {
		devices,
		loading,
		error,
		refresh: fetchDevices,
	};
};

