import Spinner from "@/components/Spinner";
import EditPhoneSc from "@/components/user/phone/EditPhoneSc";
import { notFound } from "next/navigation";
import { Suspense } from "react";

const UserPhonePage = async(props:{params: Promise<{postId:string,userId:string}>}) => {
    const params = await props.params;
    const userId = Number(params.userId);
    if(isNaN(userId))notFound();

    return (
        <div className="flex items-center justify-center">
            <div className="flex flex-col items-center justify-center w-full mx-1 sm:mx-3">
                <h2 className="text-2xl text-blue-500 font-bold my-5">EditedPostForm</h2>
                <Suspense fallback={<Spinner/>}>
                    <EditPhoneSc userId={userId}/>
                </Suspense>
            </div>
        </div>
    )
}

export default UserPhonePage;
