import React, { useState } from "react";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { ScanCreateData } from "@/types";

interface ScanFormProps {
	onSubmit: (data: ScanCreateData) => Promise<void>;
	isLoading?: boolean;
	defaultNetwork?: string;
}

export const ScanForm: React.FC<ScanFormProps> = ({
	onSubmit,
	isLoading = false,
	defaultNetwork = "192.168.1.0/24",
}) => {
	const [targetNetwork, setTargetNetwork] = useState<string>(defaultNetwork);
	const [scanName, setScanName] = useState<string>("");

	const handleSubmit = async (e: React.FormEvent) => {
		e.preventDefault();
		await onSubmit({
			target_network: targetNetwork,
			name: scanName || undefined,
		});
		setScanName("");
	};

	return (
		<Card>
			<CardHeader>
				<CardTitle>Новое сканирование</CardTitle>
				<CardDescription>
					Введите сеть для сканирования (например: 192.168.1.0/24)
				</CardDescription>
			</CardHeader>
			<CardContent>
				<form onSubmit={handleSubmit} className="space-y-4">
					<div className="space-y-2">
						<Label htmlFor="network">Адрес сети (CIDR)</Label>
						<Input
							id="network"
							placeholder="192.168.1.0/24"
							value={targetNetwork}
							onChange={(e) => setTargetNetwork(e.target.value)}
							required
						/>
					</div>
					<div className="space-y-2">
						<Label htmlFor="name">Название (опционально)</Label>
						<Input
							id="name"
							placeholder="Сканирование домашней сети"
							value={scanName}
							onChange={(e) => setScanName(e.target.value)}
						/>
					</div>
					<Button
						type="submit"
						disabled={isLoading}
						className="w-full"
					>
						{isLoading
							? "Сканирование..."
							: "Запустить сканирование"}
					</Button>
				</form>
			</CardContent>
		</Card>
	);
};

