import { ChangeEvent, useActionState, useState } from "react";
import AlertError from '../AlertError';
import { resetPassConfirm } from '@/actions/resetPassActions';
import { validationForAuthenticationPassword, validationForPassword } from "@/lib/seculity/validation";

const ResetPassConfirm = ({
    email
}:{
    email:string
}) => {
    const [state, formAction,isPending] = useActionState(
        resetPassConfirm,
        {errMsg:''}
    );
    const [resetPassConfirmForm,setResetPassConfirmForm] = useState({
        authenticationPassword:['',''],//[値,エラー文字]
        password:['','']//[値,エラー文字]
    });

    const handleChange = (e:ChangeEvent<HTMLInputElement|HTMLTextAreaElement>) => {
        const inputName = e.target.name;
        const inputVal = e.target.value;
        setResetPassConfirmForm({...resetPassConfirmForm,[inputName]:[inputVal,'']})
    }

    const handleAction = (formData:FormData) => {
        ///////////
        //■[ formDataのバリデーション ]
        const {authenticationPassword,password} = resetPassConfirmForm;
        //authenticationPassword
        let result = validationForAuthenticationPassword(authenticationPassword[0]);
        if( !result.result )authenticationPassword[1]=result.message;
        //password
        result = validationForPassword(password[0]);
        if( !result.result )password[1]=result.message;
        //name,phoneNumber,passwordのvalidation結果を反映
        if(authenticationPassword[1] || password[1]){
            setResetPassConfirmForm({authenticationPassword,password});
            return alert('入力内容に問題があります');
        }
        ///////////
        //■[ resetPassConfirmを実行 ]
        formAction(formData)
    }

    return(<>
        <div className="flex items-center justify-center">
            <div className="flex flex-col items-center justify-center w-full max-w-md">
                <p className='text-red-600 text-center'>
                    ✉{email}<br/>認証パスワードを送信しました
                </p>

                {state.errMsg && <AlertError errMessage={state.errMsg} reloadBtFlag={true}/>}

                <form 
                    action={handleAction}
                    className="mt-3 bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4 w-full max-w-md"
                >
                    <input
                        name='email'
                        type='hidden'
                        required={true}
                        defaultValue={email}
                    />
                    <div className="mb-4">
                        <label className='block text-gray-700 text-md font-bold'>6桁認証番号<em>*</em></label>
                        <span className='text-xs text-gray-500'>6桁の半角数字を入力して下さい</span>
                        <input
                            name='authenticationPassword'
                            type='text'
                            onChange={handleChange}
                            defaultValue={resetPassConfirmForm.authenticationPassword[0]}
                            required={true}
                            placeholder="認証パスワード"
                            className={`
                                ${resetPassConfirmForm.authenticationPassword[1]&&'border-red-500'} 
                                bg-gray-100 shadow appearance-none break-all border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline
                            `}
                        />
                        {resetPassConfirmForm.authenticationPassword[1] && <span className='text-red-500 text-xs italic'>{resetPassConfirmForm.authenticationPassword[1]}</span>}
                    </div>
                    <div className="mb-6">
                        <label className='block text-gray-700 text-md font-bold'>新規パスワード<em>*</em></label>
                        <span className='text-xs text-gray-500 block'>5文字以上の半角の英数字を入力して下さい</span>
                        <input
                            name='password'
                            type='password'
                            defaultValue={resetPassConfirmForm.password[0]}
                            onChange={handleChange}
                            required={true}
                            placeholder="新規パスワード"
                            className={`
                                ${resetPassConfirmForm.password[1]&&'border-red-500'} 
                                bg-gray-100 shadow appearance-none break-all border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline
                            `}
                        />
                        {resetPassConfirmForm.password[1] && <span className='text-red-500 text-xs italic'>{resetPassConfirmForm.password[1]}</span>}
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
                            {isPending ? '・・Loading・・' : 'Submit'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </>);
}
export default ResetPassConfirm;