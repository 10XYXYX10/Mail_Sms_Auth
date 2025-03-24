import { Metadata } from "next";

export async function generateMetadata(): Promise<Metadata> {
  return{
    robots: {
      index: false,   // 検索結果に表示しない
      follow: false   // リンクもたどらない
    }
  }
}

const AuthLayout = ({
    children,
}: Readonly<{
    children: React.ReactNode;
}>) => {
  return (
    <div>
      {children}
    </div>
  )
}
export default AuthLayout;
