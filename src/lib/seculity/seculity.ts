import { cookies } from 'next/headers';
import prisma from '@/lib/prisma';
import { AuthUser } from '@/lib/types';
import * as jose from 'jose';//middlewareで動かす場合、jsonwebtokenではエラーとなる

const jwtKeyFromEnv = process.env.JWT_HASH_KEY as string;
const jwtKeyUint8Array = new TextEncoder().encode(jwtKeyFromEnv);

//認証パスワード：6桁のランダムな数値
export const generateRandomNumber6 = ():number => {
    return Math.floor(Math.random() * 900000) + 100000;
}

export const jwtAccessTokenEncode = async({
    objectData
}:{
    objectData:AuthUser;
}):Promise<{
    result:boolean;
    messag:string;
    data:string;
}> => {
    try{
        const token = await new jose.SignJWT(objectData)
            .setProtectedHeader({ alg: 'HS256' })
            .setExpirationTime('2h')
            .sign(jwtKeyUint8Array);
        return {
            result:true,
            messag:'success',
            data:token
        };
    }catch(err){
        const errMessage = err instanceof Error ?  err.message : `Internal Server Error.`;
        return {
            result:false,
            messag:errMessage,
            data:'',
        };
    }
}

export const jwtAccessTokenDecode = async ({
    jwtEncoded
}:{
    jwtEncoded:string;
}):Promise<{
    result:boolean;
    messag:string;
    data:string|jose.JWTPayload;
}> => {
    try{
        const { payload } = await jose.jwtVerify(jwtEncoded, jwtKeyUint8Array);
        return {
            result:true,
            messag:'success',
            data:payload
        };
    }catch(err){
        const errMessage = err instanceof Error ?  `decoded err.${err.message}` : `Internal Server Error.`;
        return {
            result:false,
            messag:errMessage,
            data:'',
        };
    }   
}

export const security = async (jwtEncodedStr?:string):Promise<{
    result:boolean;
    data:AuthUser|null;
    message:string,
}> => {
    try{
        // await new Promise((resolve) => setTimeout(resolve, 6000))
        
        //////////
        //■[ jwt認証 ]
        const jwtEncoded = jwtEncodedStr ? jwtEncodedStr : (await cookies()).get('accessToken')?.value;
        if(!jwtEncoded)throw new Error('Authentication error.');

        const jwtDecodeResult = await jwtAccessTokenDecode({jwtEncoded});
        if(!jwtDecodeResult.result){
            if(jwtEncoded && !jwtEncodedStr)(await cookies()).delete('accessToken');
            throw new Error('Authentication error.' + jwtDecodeResult.messag);
        }

        const jwtDecoded = jwtDecodeResult.data;
        if(typeof jwtDecoded !== 'object'){
            if(jwtEncoded && !jwtEncodedStr)(await cookies()).delete('accessToken');
            throw new Error('Authentication error.');
        }
        const id = jwtDecoded.id as number;
        const name = jwtDecoded.name as string;
        if(!id || !name){
            if(jwtEncoded && !jwtEncodedStr)(await cookies()).delete('accessToken');
            throw new Error('Authentication error.');
        }

        //////////
        //■[ userの存在確認 ]
        //・middlewareでの認証:JWTのみチェック
        //・create,update,delete：JWT＋DBでデータチャック
        if(!jwtEncodedStr){
            const checkUser = await prisma.user.findUnique({
                where:{
                    id,
                    name,
                },
            });
            if(!checkUser){
                if(jwtEncoded && !jwtEncodedStr)(await cookies()).delete('accessToken');
                throw new Error('Authentication error.');
            }            
        }

        //////////
        //■[ return ]
        return {
            result:true,
            data:{
                id,
                name,
            },
            message:'success',
        }

    }catch(err){
        const errMessage = err instanceof Error ?  err.message : `Internal Server Error.`;
        return {
            result:false,
            data:null,
            message:errMessage,
        };
    }
}

export const saveAccessTokenInCookies = async({
    id,
    name,
}:{
    id:number;
    name:string;
}):Promise<{
    result:boolean;
    message:string;
}> => {
    try{
        //////////
        //■[ jwtトークン生成 ]
        const {result,messag,data} = await jwtAccessTokenEncode({objectData:{id,name}});
        if(!result)throw new Error(messag);
        const token = data;

        //////////
        //■[ jwtトークンをcookieに保存 ]
        (await cookies()).set({
            name: 'accessToken',
            value: token,
            httpOnly: true, //クライアントサイドのJavaScriptでの操作を不可に
            sameSite: 'strict', //今回は、front,back共にNext.jsで作成しているので、cookieが同一サイト内のリクエストにのみ送信されるように設定
            secure: true, //セキュリティを強化のため、HTTPS接続でのみクッキーを送信
        });
        
        //////////
        //■[ return ]
        return {result:true,message:'success'}
    }catch(err){
        const errMessage = err instanceof Error ?  err.message : `Internal Server Error.`;
        return {result:false,message:errMessage}
    }
}
