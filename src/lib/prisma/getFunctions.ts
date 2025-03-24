import prisma from "@/lib/prisma"

export const getPhoneLastNumber = async({
    userId
 }:{
    userId:number
 }):Promise<{
    success:boolean
    errMsg?:string
    phoneLastNumber?:string
 }> => {
    try{
        //////////
        //■[ データ取得 ]
        const userData = await prisma.user.findUnique({
            where:{
                id:userId
            },
            select:{
                Phone:{
                    select:{
                        hashedPhoneNumber:true
                    }
                }
            }
        });
        if(!userData)return {success:false, errMsg:'No permission.'}
        //////////
        //■[ データ整形 ]
        const hashedPhoneNumber = userData.Phone?.[0]?.hashedPhoneNumber || '';
        const phoneLastNumber = hashedPhoneNumber ? hashedPhoneNumber.slice(-4) : '';
        
        //////////
        //■[ return ]
        return {success:true,phoneLastNumber}

    }catch(err){
        const message = err instanceof Error ?  err.message : `Internal Server Error.`;
        return {success:false, errMsg:message}
    }
}
