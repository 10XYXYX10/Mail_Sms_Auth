'use client'
import { useState } from "react";
import SignUp from "./SignUp";
import SignIn from "./SignIn";

const AuthUser = () => {
    const [signUpFlag,setSignUpFlag] = useState(false);

    return (
        <div className='h-screen bg-gray-200'>
            {signUpFlag ? (<>
                <button 
                    onClick={()=>setSignUpFlag(false)}
                    className='mt-5 ml-5 px-2 py-1 text-white text-sm border border-blue-600 bg-blue-500 hover:bg-blue-400 rounded-sm'
                >
                    ログインに切り替え
                </button>
                <SignUp/>
            </>) : (<>
                <button
                    onClick={()=>setSignUpFlag(true)}
                    className='mt-5 ml-5 px-2 py-1 text-white text-sm border border-blue-600 bg-blue-500 hover:bg-blue-400 rounded-sm'
                >
                    新規作成に切り替え
                </button>
                <SignIn/>
            </>)}
        </div>
    )
}

export default AuthUser
