'use client'
import { ChangeEvent, FormEvent, useState } from "react";
import AlertError from '@/components/AlertError';
import { validationForPhoneNumber } from "@/lib/seculity/validation";
import EditPhoneConfirm from "./EditPhoneConfirm";
import axios from "axios";
import { useRouter } from "next/navigation";
import SpinnerModal from "@/components/SpinnerModal";
const apiUrl = process.env.NEXT_PUBLIC_API_URL as string;

export default function EditPhoneRequest({
    phoneLastNumber
 }:{
    phoneLastNumber:string
 }) {
    const router = useRouter();
    const [loading,setLoading] = useState(false);
    const [error,setError] = useState('');
    const [phoneForm,setPhoneForm] = useState({
      phoneNumber:['',''],//[値,バリデーションエラー文字]
    });
    const [processNum,setProcessNum] = useState<1|2>(1);

    const handleChange = (e:ChangeEvent<HTMLInputElement|HTMLTextAreaElement>) => {
        const inputName = e.target.name;
        const inputVal = e.target.value;
        setPhoneForm({...phoneForm,[inputName]:[inputVal,'']})
    }

    const handleSubmmit = async(e:FormEvent<HTMLFormElement>) => {
        e.preventDefault()
        setLoading(true);//ローディング状態でボタンを非活性に
        setError('');
        
        ///////////
        //◆【バリデーション】
        const {phoneNumber} = phoneForm;
        const result = validationForPhoneNumber(phoneNumber[0]);
        if( !result.result ){
            phoneNumber[1]=result.message;
            setPhoneForm({phoneNumber});
            setLoading(false);
            return alert('入力内容に問題があります');
        }

        //////////
        //◆【通信】
        try {
            await axios.put(
                `${apiUrl}/user/phone`,
                {
                    phoneNumber:phoneNumber[0],
                }
            );
            setProcessNum(2);
        } catch (err) { 
            let message = 'Something went wrong. Please try again.';
            if (axios.isAxiosError(err)) {
                if(err.response?.data.message)message = err.response.data.message;
                //401,Authentication failed.
                if(err.response?.status && err.response.status===401){
                    setLoading(false);
                    alert(message);
                    router.push('/auth');
                    return;
                }
            } else if (err instanceof Error) {
                message = err.message;
            }
            alert(message);
            setError(message);
        }
        setLoading(false);
    }

    return (<>
        <div className="flex items-center justify-center mt-5">
            <div className="flex flex-col items-center justify-center w-full max-w-md">
                {loading && <SpinnerModal/>}
                {error && <AlertError errMessage={error} reloadBtFlag={false}/>}
                {processNum===1
                    ?(<> 
                        <form
                            onSubmit={handleSubmmit}
                            className="bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4 w-full max-w-md"
                        >
                            <div className="mb-4">
                                <label className='block text-gray-700 text-md font-bold'>日本の携帯電話番号<em>*</em></label>
                                {phoneLastNumber && <span className='text-xs text-gray-500'>xxx-xxxx-{phoneLastNumber}</span>}
                                <input
                                    name='phoneNumber'
                                    type='text'
                                    defaultValue={phoneForm.phoneNumber[0]}
                                    onChange={handleChange}
                                    required={true}
                                    placeholder="09011112222"
                                    className={`
                                        ${phoneForm.phoneNumber[1]&&'border-red-500'} 
                                        bg-gray-100 shadow appearance-none break-all border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline
                                    `}
                                />
                                {phoneForm.phoneNumber[1] && <span className='text-red-500 text-xs italic'>{phoneForm.phoneNumber[1]}</span>}
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
                                    {loading ? '・・Loading・・' : 'Submmit'}
                                </button>
                            </div>
                        </form>
                    </> ):(
                        <EditPhoneConfirm 
                            apiUrl={apiUrl}
                            phoneNumber={phoneForm.phoneNumber[0]} 
                            setProcessNum={setProcessNum}
                            setError={setError}
                            loading={loading}
                            setLoading={setLoading}
                        />
                    )
                }
            </div>
        </div>

    </>)
}