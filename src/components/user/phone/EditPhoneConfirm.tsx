import { ChangeEvent, Dispatch, FormEvent, SetStateAction, useState } from "react";
import { validationForAuthenticationPassword } from "@/lib/seculity/validation";
import { useRouter } from "next/navigation";
import axios from "axios";

const EditPhoneConfirm = ({
    apiUrl,
    phoneNumber,
    setProcessNum,
    setError,
    loading,
    setLoading,
}:{
    apiUrl:string
    phoneNumber:string
    setProcessNum:Dispatch<SetStateAction<1 | 2>>
    setError:Dispatch<SetStateAction<string>>
    loading:boolean
    setLoading: Dispatch<SetStateAction<boolean>>
}) => {
    const router = useRouter();
    const [smsForm,setSmsForm] = useState({
        authenticationPassword:['',''],//[値,エラー文字]
    });

    const handleChange = (e:ChangeEvent<HTMLInputElement|HTMLTextAreaElement>) => {
        const inputName = e.target.name;
        const inputVal = e.target.value;
        setSmsForm({...smsForm,[inputName]:[inputVal,'']})
    }

    const handleSubmit = async(e:FormEvent<HTMLFormElement>) => {
        e.preventDefault()
        setLoading(true);//ローディング状態でボタンを非活性に
        setError('');
    
        ///////////
        //■[ formDataのバリデーション ]
        const {authenticationPassword} = smsForm;
        //authenticationPassword
        const {result,message} = validationForAuthenticationPassword(authenticationPassword[0]);
        if( !result ){
            authenticationPassword[1]=message;
            setSmsForm({authenticationPassword});
            setLoading(false);
            return alert('入力内容に問題があります');
        }

        //////////
        //■[ 通信 ]
        try {
            await axios.patch(
                `${apiUrl}/user/phone`,
                {
                    authenticationPassword:authenticationPassword[0],
                    phoneNumber,
                }
            );
            alert('Success.')
            setProcessNum(1);
        } catch (err) { 
            let message = 'Something went wrong. Please try again.';
            if (axios.isAxiosError(err)) {
                if(err.response?.data.message)message = err.response.data.message;
                //401,Authentication failed.
                if(err.response?.status ){
                    const statusCode = err.response.status;
                    if(statusCode===401){
                        alert(message);
                        return router.push('/auth');             
                    }else if(statusCode===408){
                        setProcessNum(1);
                    }
                }
            } else if (err instanceof Error) {
                message = err.message;
            }
            alert(message);
            setError(message);
        }
        setLoading(false);
    }

    return(<>
        <div className="flex items-center justify-center">
            <div className="flex flex-col items-center justify-center w-full max-w-md">
                <p className='text-red-600 text-center'>
                    ☎{phoneNumber}<br/>認証パスワードを送信しました
                </p>
                <form 
                    onSubmit={handleSubmit}
                    className="mt-3 bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4 w-full max-w-md"
                >
                    <input
                        name='phoneNumber'
                        type='hidden'
                        required={true}
                        defaultValue={phoneNumber}
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
                                ${loading&&'cursor-not-allowed'}
                            `}
                            disabled={loading}
                            type="submit"
                        >
                            {loading ? '・・Loading・・' : 'Submit'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </>);
}
export default EditPhoneConfirm;