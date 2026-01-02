export interface Device {
	id: number;
	ip_address: string;
	mac_address?: string;
	hostname?: string;
	device_type?: string;
	manufacturer?: string;
	model?: string;
	operating_system?: string;
	open_ports?: string;
	last_seen: string;
	created_at: string;
	updated_at: string;
}

export interface Vulnerability {
	id: number;
	device_id: number;
	title: string;
	description?: string;
	severity: VulnerabilitySeverity;
	cve_id?: string;
	port?: number;
	service?: string;
	recommendation: string;
	fixed: string;
	created_at: string;
	updated_at: string;
}

export interface DeviceWithVulnerabilities extends Device {
	vulnerabilities: Vulnerability[];
}

export interface Scan {
	id: number;
	name?: string;
	target_network: string;
	status: ScanStatus;
	started_at: string;
	completed_at?: string;
	devices_found: number;
	created_at: string;
}

export type ScanStatus = "pending" | "running" | "completed" | "failed";

export type VulnerabilitySeverity = "low" | "medium" | "high" | "critical";

export interface PortInfo {
	port: number;
	service: string;
	version?: string;
	product?: string;
}

export interface ScanCreateData {
	target_network: string;
	name?: string;
}

