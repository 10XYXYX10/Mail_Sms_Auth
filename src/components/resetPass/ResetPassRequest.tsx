'use client'
import { ChangeEvent, useActionState, useState } from "react";
import AlertError from '../AlertError';
import { resetPassRequest } from '@/actions/resetPassActions';
import ResetPassConfirm from "./ResetPassConfirm";
import { validationForEmail, validationForPhoneNumber, validationForWord } from "@/lib/seculity/validation";

export default function ResetPassRequest() {
    const [state, formAction, isPending] = useActionState(
        resetPassRequest,
        {
            success:false,
            errMsg:'',
        }
    );
    const [resetPassRequestForm,setResetPassRequestForm] = useState({
      email:['',''],//[値,エラー文字]
    });

    const handleChange = (e:ChangeEvent<HTMLInputElement|HTMLTextAreaElement>) => {
        const inputName = e.target.name;
        const inputVal = e.target.value;
        setResetPassRequestForm({...resetPassRequestForm,[inputName]:[inputVal,'']})
    }

    const handleAction = (formData:FormData) => {
        ///////////
        //◆【formDataのバリデーション】
        const {email} = resetPassRequestForm;
        //name
        const result = validationForEmail(email[0]);
        if( !result.result ){
            email[1]=result.message;
            setResetPassRequestForm({email});
            return alert('入力内容に問題があります');
        }
        ///////////
        //■[ resetPassRequestを実行 ]
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
                                    defaultValue={resetPassRequestForm.email[0]}
                                    onChange={handleChange}
                                    required={true}
                                    placeholder="メールアドレス"
                                    className={`
                                        ${resetPassRequestForm.email[1]&&'border-red-500'} 
                                        bg-gray-100 shadow appearance-none break-all border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline
                                    `}
                                />
                                {resetPassRequestForm.email[1] && <span className='text-red-500 text-xs italic'>{resetPassRequestForm.email[1]}</span>}
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
                                    {isPending ? '・・Loading・・' : 'reset password'}
                                </button>
                            </div>
                        </form>
                    </> ):(
                        <ResetPassConfirm email={resetPassRequestForm.email[0]}/>
                    )
                }
            </div>
        </div>

    </>)
}