import { ChangeEvent, useActionState, useState } from "react";
import AlertError from '../AlertError';
import { signIn } from '@/actions/authActions';
import MailAuth from './MailAuth';
import { validationForPassword, validationForEmail, validationForWord } from "@/lib/seculity/validation";
import Link from "next/link";

export default function SignIn() {
    const [state, formAction, isPending] = useActionState(
        signIn,
        {
            success:false,
            errMsg:'',
        }
    );
    const [signForm,setSignForm] = useState({
      email:['',''],//[値,エラー文字]
      password:['','']//[値,エラー文字]
    });

    const handleChange = (e:ChangeEvent<HTMLInputElement|HTMLTextAreaElement>) => {
        const inputName = e.target.name;
        const inputVal = e.target.value;
        setSignForm({...signForm,[inputName]:[inputVal,'']})
    }

    const handleAction = (formData:FormData) => {
        ///////////
        //◆【formDataのバリデーション】
        const {email,password} = signForm;
        //email
        let result = validationForEmail(email[0]);
        if( !result.result )email[1]=result.message;
        //password
        result = validationForPassword(password[0]);
        if( !result.result )password[1]=result.message;
        //email,passwordのvalidation結果を反映
        if(email[1] || password[1]){
            setSignForm({email,password});
            return alert('入力内容に問題があります');
        }
        ///////////
        //■[ signInを実行 ]
        formAction(formData)
    }

    return (<>
        <div className="flex items-center justify-center mt-5">
            <div className="flex flex-col items-center justify-center w-full max-w-md">
                {!state.success
                    ?(<> 
                        {state.errMsg && <AlertError errMessage={state.errMsg} reloadBtFlag={false}/>}
                        <form
                            action={handleAction}
                            className="bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4 w-full max-w-md"
                        >
                            <div className="mb-4">
                                <label className='block text-gray-700 text-md font-bold'>メールアドレス<em>*</em></label>
                                <span className='text-xs text-gray-500'>メールアドレス</span>
                                <input
                                    name='email'
                                    type='text'
                                    defaultValue={signForm.email[0]}
                                    onChange={handleChange}
                                    required={true}
                                    placeholder="メールアドレス"
                                    className={`
                                        ${signForm.email[1]&&'border-red-500'} 
                                        bg-gray-100 shadow appearance-none break-all border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline
                                    `}
                                />
                                {signForm.email[1] && <span className='text-red-500 text-xs italic'>{signForm.email[1]}</span>}
                            </div>
                            <div className="mb-6">
                                <label className='block text-gray-700 text-md font-bold'>パスワード<em>*</em></label>
                                <span className='text-xs text-gray-500 block'>5文字以上の半角の英数字を入力して下さい</span>
                                <input
                                    name='password'
                                    type='password'
                                    defaultValue={signForm.password[0]}
                                    onChange={handleChange}
                                    required={true}
                                    placeholder="パスワード"
                                    className={`
                                        ${signForm.password[1]&&'border-red-500'} 
                                        bg-gray-100 shadow appearance-none break-all border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline
                                    `}
                                />
                                {signForm.password[1] && <span className='text-red-500 text-xs italic'>{signForm.password[1]}</span>}
                            </div>
                            <div className='flex items-center justify-between'> 
                                <button
                                    className={`
                                    bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline 
                                    ${isPending&&'cursor-not-allowed'}
                                    `}
                                    disabled={isPending}
                                    type="submit"
                                >
                                    {isPending ? '・・Loading・・' : 'SignIn'}
                                </button>
                            </div>
                            <Link 
                                href="/resetPass" 
                                className="inline-block align-middle mt-3 font-bold text-sm text-blue-400 hover:text-blue-600"
                            >
                                passwordをお忘れですか？
                            </Link>
                        </form>
                    </> ):(
                        <MailAuth email={signForm.email[0]} typeValue={'SignIn'}/>
                    )
                }
            </div>
        </div>

    </>)
}