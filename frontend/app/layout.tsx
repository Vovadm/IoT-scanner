import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin", "cyrillic"] });

export const metadata: Metadata = {
	title: "IoT Scanner - Система безопасности IoT устройств",
	description: "Сканирование и анализ уязвимостей IoT устройств в вашей сети",
};

export default function RootLayout({
	children,
}: {
	children: React.ReactNode;
}) {
    return (
		<html lang="ru">
			<body className={inter.className}>{children}</body>
		</html>
	);
}
