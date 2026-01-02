import React, { ReactNode } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { LucideIcon } from "lucide-react";

interface StatsCardProps {
	title: string;
	value: string | number;
	icon: LucideIcon;
	className?: string;
}

export const StatsCard: React.FC<StatsCardProps> = ({
	title,
	value,
	icon: Icon,
	className = "",
}) => {
	return (
		<Card>
			<CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
				<CardTitle className="text-sm font-medium">{title}</CardTitle>
				<Icon className="h-4 w-4 text-muted-foreground" />
			</CardHeader>
			<CardContent>
				<div className={`text-2xl font-bold ${className}`}>{value}</div>
			</CardContent>
		</Card>
	);
};
