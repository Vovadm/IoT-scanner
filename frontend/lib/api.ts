import {
	Device,
	Vulnerability,
	DeviceWithVulnerabilities,
	Scan,
	ScanCreateData,
} from "@/types";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export async function getDevices(): Promise<Device[]> {
	const res = await fetch(`${API_URL}/api/devices/`);
	if (!res.ok) throw new Error("Failed to fetch devices");
	return res.json();
}

export async function getDevice(
	id: number
): Promise<DeviceWithVulnerabilities> {
	const res = await fetch(`${API_URL}/api/devices/${id}`);
	if (!res.ok) throw new Error("Failed to fetch device");
	return res.json();
}

export async function createScan(
	targetNetwork: string,
	name?: string
): Promise<{ scan: Scan; message: string }> {
	const res = await fetch(`${API_URL}/api/scans/`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ target_network: targetNetwork, name }),
	});
	if (!res.ok) throw new Error("Failed to create scan");
	return res.json();
}

export async function getScans(): Promise<Scan[]> {
	const res = await fetch(`${API_URL}/api/scans/`);
	if (!res.ok) throw new Error("Failed to fetch scans");
	return res.json();
}

export async function getScan(id: number): Promise<Scan> {
	const res = await fetch(`${API_URL}/api/scans/${id}`);
	if (!res.ok) throw new Error("Failed to fetch scan");
	return res.json();
}

export async function getVulnerabilities(
	deviceId?: number,
	severity?: string
): Promise<Vulnerability[]> {
	const params = new URLSearchParams();
	if (deviceId) params.append("device_id", deviceId.toString());
	if (severity) params.append("severity", severity);
	const res = await fetch(`${API_URL}/api/vulnerabilities/?${params}`);
	if (!res.ok) throw new Error("Failed to fetch vulnerabilities");
	return res.json();
}

export async function updateVulnerability(
	id: number,
	fixed: boolean
): Promise<Vulnerability> {
	const res = await fetch(`${API_URL}/api/vulnerabilities/${id}`, {
		method: "PATCH",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ fixed: fixed ? "true" : "false" }),
	});
	if (!res.ok) throw new Error("Failed to update vulnerability");
	return res.json();
}
