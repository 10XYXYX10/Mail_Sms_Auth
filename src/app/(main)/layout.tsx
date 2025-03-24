import Header from '@/components/header/Header';

const MainLayout = ({
    children,
}: Readonly<{
    children: React.ReactNode;
}>) => {
  return (
    <div>
      <Header/>
      <div className='container mx-auto'>
        {children}
      </div>
    </div>
  )
}

export default MainLayout;
