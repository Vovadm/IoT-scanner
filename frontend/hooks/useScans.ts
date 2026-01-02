import { useState, useEffect, useCallback } from "react";
import { Scan } from "@/types";
import { getScans } from "@/lib/api";

interface UseScansReturn {
	scans: Scan[];
	loading: boolean;
	error: string | null;
	refresh: () => Promise<void>;
}

export const useScans = (): UseScansReturn => {
	const [scans, setScans] = useState<Scan[]>([]);
	const [loading, setLoading] = useState<boolean>(true);
	const [error, setError] = useState<string | null>(null);

	const fetchScans = useCallback(async () => {
		try {
			setLoading(true);
			setError(null);
			const data = await getScans();
			setScans(data);
		} catch (err) {
			const errorMessage =
				err instanceof Error
					? err.message
					: "Ошибка загрузки сканирований";
			setError(errorMessage);
			console.error("Error loading scans:", err);
		} finally {
			setLoading(false);
		}
	}, []);

	useEffect(() => {
		fetchScans();
	}, [fetchScans]);

	return {
		scans,
		loading,
		error,
		refresh: fetchScans,
	};
};

