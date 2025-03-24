import { getPhoneLastNumber } from "@/lib/prisma/getFunctions";
import EditPhoneRequest from "./EditPhoneRequest";

const EdidPhoneSc = async({
    userId
 }:{
    userId:number
 }) => {
   //await new Promise((resolve) => setTimeout(resolve, 6000))
   const { success,errMsg,phoneLastNumber} = await getPhoneLastNumber({userId});
   if(!success || phoneLastNumber===undefined)throw new Error(errMsg ? errMsg : 'Something went wrong.');

   return <EditPhoneRequest phoneLastNumber={phoneLastNumber}/>
}
export default EdidPhoneSc
