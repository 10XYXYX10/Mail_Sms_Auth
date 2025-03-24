import type { Metadata } from "next";
import "./globals.css";

const title = "SMS AUTH";
const description = "Next.jsとVonageを活用して、SMS二段階認証を導入したセキュアなアプリケーションを開発しました。迅速かつ安全なユーザー認証を実現します。";

export const metadata: Metadata = {
  title,
  description,
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {

  return (
    <html lang="ja">
      <body>
        {children}
      </body>
    </html>
  );
}
