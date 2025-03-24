import { Metadata } from "next";

export async function generateMetadata(): Promise<Metadata> {
    return{
      robots: {
        index: false,   // 検索結果に表示しない
        follow: false   // リンクもたどらない
      }
    }
}

const UserLayout = ({
    children,
}: Readonly<{
    children: React.ReactNode;
}>) => {
  return (<>
    {children}
  </>)
}
export default UserLayout;


