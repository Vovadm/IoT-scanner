import { ScanStatus, VulnerabilitySeverity } from "@/types/enums";

export const SCAN_STATUS_VARIANTS: Record<
	ScanStatus,
	"default" | "secondary" | "destructive"
> = {
	[ScanStatus.PENDING]: "secondary",
	[ScanStatus.RUNNING]: "default",
	[ScanStatus.COMPLETED]: "default",
	[ScanStatus.FAILED]: "destructive",
};

export const SCAN_STATUS_TEXTS: Record<ScanStatus, string> = {
	[ScanStatus.PENDING]: "Ожидание",
	[ScanStatus.RUNNING]: "Выполняется",
	[ScanStatus.COMPLETED]: "Завершено",
	[ScanStatus.FAILED]: "Ошибка",
};

export const VULNERABILITY_SEVERITY_COLORS: Record<
	VulnerabilitySeverity,
	string
> = {
	[VulnerabilitySeverity.LOW]:
		"bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300",
	[VulnerabilitySeverity.MEDIUM]:
		"bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300",
	[VulnerabilitySeverity.HIGH]:
		"bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300",
	[VulnerabilitySeverity.CRITICAL]:
		"bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300",
};

export const VULNERABILITY_SEVERITY_TEXTS: Record<
	VulnerabilitySeverity,
	string
> = {
	[VulnerabilitySeverity.LOW]: "Низкая",
	[VulnerabilitySeverity.MEDIUM]: "Средняя",
	[VulnerabilitySeverity.HIGH]: "Высокая",
	[VulnerabilitySeverity.CRITICAL]: "Критическая",
};

