'use server'
import { validationForAuthenticationPassword, validationForPassword, validationForEmail, validationForWord } from "@/lib/seculity/validation";
import { generateRandomNumber6, saveAccessTokenInCookies, security } from "@/lib/seculity/seculity";
import prisma from "@/lib/prisma";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";
import { SignFormState, AuthUser} from "@/lib/types";
import * as bcrypt from 'bcrypt';
import { cookies } from "next/headers";
import { redirect } from 'next/navigation';
import { rateLimit } from "@/lib/seculity/upstash";
import { sendMail } from "@/lib/nodemailer";

const emailOrPasswordErr = 'The value you entered is incorrect. Please try again.';//攻撃されることを想定し、どちらが間違っていたか予測がつかないように

export const loginCheck = async ():Promise<{
    success: boolean
    errMsg: string
    authUser?: AuthUser
}> => {
    try{
        //////////
        //■[ セキュリティー ]
        const {result,data,message} = await security();
        if(!result || !data)return {success:false, errMsg:message}

        //////////
        //■[ return ]
        return {success:true, errMsg:'', authUser:data}
    }catch(err){
        const message = err instanceof Error ?  err.message : `Internal Server Error.`;
        return {success:false, errMsg:message}
    }
}

//新規User作成
export const signUp = async (
    state: SignFormState, 
    formData: FormData
 ):Promise<SignFormState> => {
    try{
        //////////
        //■[ rateLimit ]
        const {success,message} = await rateLimit()
        if(!success) return {...state, errMsg:message};
        //return {success:false, errMsg:'XXX'};//テスト:rateLimit

        //////////
        //■[ formData ]
        // formDataから値を取得
        const name = formData.get('name') as string;
        const email = formData.get('email') as string;
        const password = formData.get('password') as string;
        // Required validation
        if (!name || !email || !password) return {...state, errMsg:'Bad request error.'};

        //////////
        //■[ validation ]:正規ルート外からのリクエストに備えての保険
        //・name
        let result = validationForWord(name);
        if(!result.result) return {...state, errMsg:'Bad request error.'};
        //・email
        result = validationForEmail(email);
        if(!result.result) return {...state, errMsg:'Bad request error.'};
        //・password
        result = validationForPassword(password);
        if(!result.result) return {...state, errMsg:'Bad request error.'};

        //////////
        //■[ 不要データの削除 ]
        prisma.user.deleteMany({
            where: {
                verifiedEmail:false,
                createdAt: {
                    lt: new Date(Date.now() - 1000 * 60 * 4)//4分経過：認証パスワードの有効期限は3分
                }
            }
        }).catch((err)=>console.log(err.message));

        //////////
        //■[ passwordをハッシュ化 ]
        //・password
        const hashedPassword = await bcrypt.hash(password, 11);

        //////////
        //■[ 6桁の認証パスワードを生成 ]
        const randomNumber6 = generateRandomNumber6();

        //////////
        //■[ transaction ]
        await prisma.$transaction(async (prismaT) => {
            //新規User作成
            await prismaT.user.create({
                data: {
                    name,
                    email,
                    hashedPassword,
                    verifiedEmail:false,
                    authenticationPassword:randomNumber6,
                },
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
        let errMsg = err instanceof Error ? err.message : `Internal Server Error.`;
        if (err instanceof PrismaClientKnownRequestError && err.code==='P2002') {// Unique制約違反のエラー
            errMsg = 'That name cannot be used. Please try another one.';
        }
        //////////
        //■[ return(処理失敗) ]
        return {...state, errMsg}
    }
};


//ログイン
export const signIn = async (
    state: SignFormState, 
    formData: FormData
 ):Promise<SignFormState> => {
    try{
        //////////
        //■[ rateLimit ]
        const {success,message} = await rateLimit()
        if(!success) return {...state, errMsg:message};
        
        //////////
        //■[ formData ]
        // formDataから値を取得
        const email = formData.get('email') as string;
        const password = formData.get('password') as string;
        // Required validation
        if (!email || !password) return {...state, errMsg:'Bad request error.'};

        //////////
        //■[ validation ]:正規ルート外からのリクエストに備えての保険
        //・email
        let result = validationForEmail(email);
        if(!result.result) return {...state, errMsg:'Bad request error.'};
        //・password
        result = validationForPassword(password);
        if(!result.result) return {...state, errMsg:'Bad request error.'};
    
        //////////
        //■[ 認証:password ]
        const checkUser = await prisma.user.findFirst({
            where:{
                email,
                verifiedEmail:true
            }
        });
        if(!checkUser)return {...state, errMsg:emailOrPasswordErr}; 
        try{
            const result = await bcrypt.compare(password, checkUser.hashedPassword);
            if(!result)return {...state, errMsg:emailOrPasswordErr}
        }catch(err){
            throw err;
        }

        //////////
        //■[ 6桁の認証パスワードを生成 ]
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

//「signUp or signIn」→ メール認証
export const mailAuth = async (
    typeValue: 'SignUp'|'SignIn',
    state: {errMsg:string},
    formData: FormData
):Promise<{errMsg:string}> => {
    let userId:number = 0;
    try{
        //////////
        //■[ rateLimit ]
        const {success,message} = await rateLimit()
        if(!success) return {...state, errMsg:message};
        
        //////////
        //■[ formDataから値を取得 ]
        // formDataから値を取得
        const email = formData.get('email') as string;
        const authenticationPassword = formData.get('authenticationPassword') as string;
        // Required validation
        if(!email || !authenticationPassword)return {errMsg:'Bad request error.'}

        //////////
        //■[ validation ]:正規ルート外からのリクエストに備えての保険
        //・name
        let result = validationForEmail(email);
        if(!result.result) return {errMsg:'Bad request error.'};
        //・authenticationPassword
        result = validationForAuthenticationPassword(authenticationPassword);
        if(!result.result) return {errMsg:'Bad request error.'};

        //////////
        //■[ userチェック～経過時間の検証 ]
        const checkUser = await prisma.user.findUnique({
          where:{
            email
          }
        });
        //Userが存在しない
        if(!checkUser)return {errMsg:`Something went wrong. Please try again.`};
        userId = checkUser.id;
        //ログインを試みたが、メールアドレスの認証が未完了
        if(typeValue=='SignIn' && !checkUser.verifiedEmail)return {errMsg:'That user is disabled. SMS authentication has not been completed.'};
        //認証パスワードが違う
        if(checkUser.authenticationPassword!==Number(authenticationPassword))return {errMsg:'Authentication password is incorrect.'};
        //経過時間の検証：3分以上経過していたらエラーとする
        const beforeTime = checkUser.updatedAt;
        const currentTime = new Date();
        const elapsedMilliseconds = currentTime.getTime() - beforeTime.getTime();// beforeTimeから現在の日時までの経過時間(ミリ秒単位)を計算
        const elapsedMinutes = elapsedMilliseconds / (1000 * 60);// 経過時間を分単位に変換
        if (elapsedMinutes >= 3){
          if(typeValue==='SignUp')await prisma.user.delete({where:{id:userId}});//User新規作成時、3分超過により認証が失敗した場合は、Userを削除
          return {errMsg:'More than 3 minutes have passed. Please try again.'};
        }

        //////////
        //■[ 新規作成時のSMS認証なら、verifiedEmail:true に更新 ]
        if(typeValue==='SignUp'){
            await prisma.user.update({
                where:{id:userId},
                data:{
                    verifiedEmail:true
                }
            });
        }

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


export const signOut = async(state: string) => {
    try{
        //////////
        //■[ jwtをサーバーサイドcookieから削除 ]
        const accessToken = (await cookies()).get('accessToken');
        if(accessToken)(await cookies()).delete('accessToken');
    }catch(err){
        //////////
        //■[ return(処理失敗) ]
        state = err instanceof Error ?  err.message : `Internal Server Error.`
        return state;
    }
    
    //////////
    //■[ 処理成功時、リダイレクト ]
    //・redirectはtry-catchの外で実行することが推奨されている:https://nextjs.org/docs/app/building-your-application/routing/redirecting
    redirect('/auth');
} 

