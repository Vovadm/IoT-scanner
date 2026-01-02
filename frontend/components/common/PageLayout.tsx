import React, { ReactNode } from "react";

interface PageLayoutProps {
	children: ReactNode;
	className?: string;
}

export const PageLayout: React.FC<PageLayoutProps> = ({
	children,
	className = "",
}) => {
	return (
		<div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800">
			<div className={`container mx-auto px-4 py-8 ${className}`}>
				{children}
			</div>
		</div>
	);
};

