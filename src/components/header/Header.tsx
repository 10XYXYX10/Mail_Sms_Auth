import Link from 'next/link'
import UserIcon from './UserIcon'
import { loginCheck } from '@/actions/authActions';

const Header = async() => {
    //*https://nextjs.org/docs/app/api-reference/functions/cookies
    //Cookiesを使用したseculity()関数を直接実行してもエラーにはならないが、公式では、Server Actions or Route Handlersから呼び出すことを推奨している。
    const {authUser} = await loginCheck()
    const user = authUser ? authUser : {id:0,name:''};

    return (<header className='bg-gradient-to-r from-blue-300 to-indigo-400 max-w-full p-3 rounded shadow-md'>
        <div className='flex items-center justify-between container mx-auto max-w-screen-lg'>
            <div>
                <Link 
                    href='/'
                    className='inline-block font-bold px-2.5 py-1 bg-gradient-to-r from-blue-600 to-indigo-600 text-transparent bg-clip-text hover:from-blue-500 hover:to-indigo-500 text-md sm:text-2xl transition duration-300'
                >
                    SmsAuth
                </Link>                
            </div>

            <div>
                <UserIcon user={user}/>
            </div>
        </div>
    </header>)
}
export default Header;
