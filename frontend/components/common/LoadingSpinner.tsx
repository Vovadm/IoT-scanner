import React from "react";

interface LoadingSpinnerProps {
	message?: string;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
	message = "Загрузка...",
}) => {
	return (
		<div className="text-center py-12">
			<p className="text-muted-foreground">{message}</p>
		</div>
	);
};

