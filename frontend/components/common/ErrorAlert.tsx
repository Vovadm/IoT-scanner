import React from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertCircle } from "lucide-react";

interface ErrorAlertProps {
	message: string;
	onClose?: () => void;
}

export const ErrorAlert: React.FC<ErrorAlertProps> = ({ message, onClose }) => {
	if (!message) return null;

	return (
		<Alert variant="destructive" className="mb-6">
			<AlertCircle className="h-4 w-4" />
			<AlertTitle>Ошибка</AlertTitle>
			<AlertDescription>{message}</AlertDescription>
		</Alert>
	);
};

