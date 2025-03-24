'use server'
import { validationForAuthenticationPassword, validationForPassword, validationForEmail, validationForWord } from "@/lib/seculity/validation";
import { generateRandomNumber6, saveAccessTokenInCookies } from "@/lib/seculity/seculity";
import prisma from "@/lib/prisma";
import * as bcrypt from 'bcrypt';
import { rateLimit } from "@/lib/seculity/upstash";
import { redirect } from "next/navigation";
import { sendMail } from "@/lib/nodemailer";

const nameOremailErr = 'The value you entered is incorrect. Please try again.';//攻撃されることを想定し、どちらが間違っていたか予測がつかないように

//■[ resetPassRequest ]
type ResetPassRequestState = {
    success: boolean
    errMsg: string
}
export const resetPassRequest = async (
    state: ResetPassRequestState, 
    formData: FormData
 ):Promise<ResetPassRequestState> => {
    try{
        // //////////
        // //■[ rateLimit ]
        // const {success,message} = await rateLimit()
        // if(!success) return {...state, errMsg:message};
        
        //////////
        //■[ formData ]
        // formDataから値を取得
        const email = formData.get('email') as string;
        // Required validation
        if (!email ) return {...state, errMsg:'Bad request error.'};

        //////////
        //■[ validation ]
        //・email
        const result = validationForEmail(email);
        if(!result.result) return {...state, errMsg:'Bad request error.'};
    
        //////////
        //■[ 認証:email ]
        //・email
        const checkUser = await prisma.user.findFirst({
            where:{
                email,
                verifiedEmail:true
            }
        });
        if(!checkUser)return {...state, errMsg:nameOremailErr}

        //////////
        //■[ 6桁の乱数を生成 ]
        const randomNumber6 = generateRandomNumber6();

        //////////
        //■[ transaction ]
        await prisma.$transaction(async (prismaT) => {
            //////////
            //■[ SMS認証 ]
            //・User の authenticationPassword & updatedAt を更新
            await prismaT.user.update({
                where:{id:checkUser.id},
                data:{
                    authenticationPassword:randomNumber6,
                    updatedAt: new Date()
                }
            });
            //認証メール送信
            const {result,message} = await sendMail({
                toEmail: email,
                subject: '二段階認証パスワード',
                text: '以下のパスワードを入力し、メールアドレス認証を完了させて下さい。有効期限は3分です。',
                html:`
                    <p>以下のパスワードを入力し、メールアドレス認証を完了させて下さい。有効期限は3分です。</p>
                    <br/>
                    <p>${randomNumber6}</p>
                `
            });
            if(!result)throw new Error(message);
        },
        {
            maxWait: 10000, // default: 2000
            timeout: 25000, // default: 5000
        }).catch((err)=>{
            throw err;
        });
        
        //////////
        //■[ return(処理成功) ]
        return {success:true, errMsg:''};
        
    }catch(err){
        //////////
        //■[ return(処理失敗) ]
        return {...state, errMsg:err instanceof Error ?  err.message : `Internal Server Error.`};
    }
};

export const resetPassConfirm = async (
    state: {errMsg:string},
    formData: FormData
):Promise<{errMsg:string}> => {
    let userId:number = 0;
    try{
        // //////////
        // //■[ rateLimit ]
        // const {success,message} = await rateLimit()
        // if(!success) return {...state, errMsg:message};
        
        console.log('resetPassConfirm')
        //////////
        //■[ formDataから値を取得 ]
        // formDataから値を取得
        const email = formData.get('email') as string;
        const password = formData.get('password') as string;
        const authenticationPassword = formData.get('authenticationPassword') as string;
        // Required validation
        if(!email || !authenticationPassword || !password)return {errMsg:'Bad request error.'}

        console.log('resetPassConfirm')
        //////////
        //■[ validation ]
        //・email
        let result = validationForEmail(email);
        if(!result.result) return {errMsg:'Bad request error.'};
        //・password
        result = validationForPassword(password);
        if(!result.result) return {errMsg:'Bad request error.'};
        //・authenticationPassword
        result = validationForAuthenticationPassword(authenticationPassword);
        if(!result.result) return {errMsg:'Bad request error.'};

        console.log('resetPassConfirm')
        //////////
        //■[ userチェック～経過時間の検証 ]
        const checkUser = await prisma.user.findUnique({
          where:{
            email,
          }
        });
        //Userが存在しない
        if(!checkUser)return {errMsg:`Something went wrong. Please try again.`};
        userId = checkUser.id;
        //電話番号の認証が未完了
        if(!checkUser.verifiedEmail)return {errMsg:'That user is disabled. SMS authentication has not been completed.'};
        //認証パスワードが違う
        if(checkUser.authenticationPassword!==Number(authenticationPassword))return {errMsg:'Authentication password is incorrect.'};
        //経過時間の検証：3分以上経過していたらエラーとする
        const beforeTime = checkUser.updatedAt;
        const currentTime = new Date();
        const elapsedMilliseconds = currentTime.getTime() - beforeTime.getTime();// beforeTimeから現在の日時までの経過時間(ミリ秒単位)を計算
        const elapsedMinutes = elapsedMilliseconds / (1000 * 60);// 経過時間を分単位に変換
        if (elapsedMinutes >= 3)return {errMsg:'More than 3 minutes have passed. Please try again.'};

        
        //////////
        //■[ passwordをハッシュ化 ~ 更新 ]
        //・passwordをハッシュ化
        const hashedPassword = await bcrypt.hash(password, 11);
        //・更新
        await prisma.user.update({
            where:{ id:checkUser.id },
            data:{ hashedPassword }
        })

        //////////
        //■[ accessToken をサーバーサイドcookiesに保存 ]
        const savedResult = await saveAccessTokenInCookies({id:userId, name:checkUser.name});
        if(!savedResult.result)throw new Error(savedResult.message);
        
    }catch(err){
        //////////
        //■[ return(処理失敗) ]
        return {errMsg:err instanceof Error ?  err.message : `Internal Server Error.`};
    }

    //////////
    //■[ 処理成功時、リダイレクト ]
    //・redirectはtry-catchの外で実行することが推奨されている:https://nextjs.org/docs/app/building-your-application/routing/redirecting
    redirect(`/user/${userId}`);
}