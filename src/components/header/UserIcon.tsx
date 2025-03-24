'use client'
import { IconDeviceMobileCog, IconUser } from '@tabler/icons-react'
import Link from 'next/link';
import SignOut from '../auth/SignOut';
import { AuthUser } from '@/lib/types';
import { usePathname } from 'next/navigation';

const UserIcon = ({
    user
 }:{
    user:AuthUser
 }) => {
    const pathname = usePathname();

    return (
        <div className='flex space-x-3'>
            {user.name && <SignOut/>}

            {user.name && pathname.startsWith('/user')&&(
                <Link
                    href={`/user/${user.id}/phone`}
                    className='p-2 hover:opacity-75 inline-block my-1'
                >
                    <IconDeviceMobileCog size={24}/>
                </Link>
            )}

            <Link
                href={user.id ? `/user/${user.id}` : '/auth'}
                //href={user.id ? `/user/${user.id}` : '/user'}「/user」としても、未ログインなら、middlewareの認証で/authへとリダイレクトされる
                className={`rounded-full p-2 hover:opacity-75 inline-block my-1 ${pathname.startsWith('/user')?'bg-red-400':'bg-gray-400'}`}
            >
                {user.name
                    ?(
                        user.name.slice(0,3)
                    ):(
                        <IconUser/>
                    )
                }
            </Link>
        </div>
    )
}
export default UserIcon;
