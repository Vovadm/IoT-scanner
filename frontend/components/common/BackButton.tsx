import React from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { ArrowLeft } from "lucide-react";

interface BackButtonProps {
	href: string;
	label?: string;
}

export const BackButton: React.FC<BackButtonProps> = ({
	href,
	label = "Назад",
}) => {
	return (
		<Link href={href}>
			<Button variant="ghost">
				<ArrowLeft className="mr-2 h-4 w-4" />
				{label}
			</Button>
		</Link>
	);
};

