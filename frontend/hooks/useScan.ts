import { useState, useCallback } from "react";
import { Scan, ScanCreateData } from "@/types";
import { createScan } from "@/lib/api";

interface UseScanReturn {
	isScanning: boolean;
	error: string | null;
	startScan: (data: ScanCreateData) => Promise<Scan | null>;
}

export const useScan = (onSuccess?: () => void): UseScanReturn => {
	const [isScanning, setIsScanning] = useState<boolean>(false);
	const [error, setError] = useState<string | null>(null);

	const startScan = useCallback(
		async (data: ScanCreateData): Promise<Scan | null> => {
			if (!data.target_network.trim()) {
				setError("Пожалуйста, введите адрес сети для сканирования");
				return null;
			}

			setIsScanning(true);
			setError(null);

			try {
				const result = await createScan(
					data.target_network,
					data.name || undefined
				);
				if (onSuccess) {
					onSuccess();
				}
				return result.scan;
			} catch (err) {
				const errorMessage =
					err instanceof Error
						? err.message
						: "Ошибка при запуске сканирования";
				setError(errorMessage);
				return null;
			} finally {
				setIsScanning(false);
			}
		},
		[onSuccess]
	);

	return {
		isScanning,
		error,
		startScan,
	};
};

