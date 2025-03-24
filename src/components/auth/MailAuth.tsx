import { ChangeEvent, useActionState, useState } from "react";
import AlertError from '../AlertError';
import { mailAuth } from '@/actions/authActions';
import { validationForAuthenticationPassword } from "@/lib/seculity/validation";

const MailAuth = ({
    email,
    typeValue,
}:{
    email:string
    typeValue: 'SignUp'|'SignIn',
}) => {
    const MailAuthWithTypeValue = mailAuth.bind(null, typeValue);
    const [state, formAction,isPending] = useActionState(
        MailAuthWithTypeValue,
        {
            errMsg:'',
        }
    );
    const [smsForm,setSmsForm] = useState({
        authenticationPassword:['',''],//[値,エラー文字]
    });

    const handleChange = (e:ChangeEvent<HTMLInputElement|HTMLTextAreaElement>) => {
        const inputName = e.target.name;
        const inputVal = e.target.value;
        setSmsForm({...smsForm,[inputName]:[inputVal,'']})
    }

    const handleAction = (formData:FormData) => {
        ///////////
        //◆【formDataのバリデーション】
        const {authenticationPassword} = smsForm;
        //authenticationPassword
        const {result,message} = validationForAuthenticationPassword(authenticationPassword[0]);
        if( !result ){
            authenticationPassword[1]=message;
            setSmsForm({authenticationPassword});
            return alert('入力内容に問題があります');
        }
        ///////////
        //■[ MailAuthを実行 ]
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
                            defaultValue={smsForm.authenticationPassword[0]}
                            required={true}
                            placeholder="認証パスワード"
                            className={`
                                ${smsForm.authenticationPassword[1]&&'border-red-500'} 
                                bg-gray-100 shadow appearance-none break-all border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline
                            `}
                        />
                        {smsForm.authenticationPassword[1] && <span className='text-red-500 text-xs italic'>{smsForm.authenticationPassword[1]}</span>}
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
export default MailAuth;