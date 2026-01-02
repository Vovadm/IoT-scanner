import React, { ReactNode } from "react";

interface PageHeaderProps {
	title: string;
	description?: string;
	action?: ReactNode;
	backButton?: ReactNode;
}

export const PageHeader: React.FC<PageHeaderProps> = ({
	title,
	description,
	action,
	backButton,
}) => {
	return (
		<div className="mb-8">
			{backButton && <div className="mb-4">{backButton}</div>}
			<div className="flex items-center justify-between">
				<div className="flex-1">
					<h1 className="text-4xl font-bold mb-2">{title}</h1>
					{description && (
						<p className="text-muted-foreground text-lg">
							{description}
						</p>
					)}
				</div>
				{action && <div>{action}</div>}
			</div>
		</div>
	);
};

