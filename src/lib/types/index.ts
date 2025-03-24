//////////
//■[ 認証 ]
export type AuthUser = {
    id:number
    name:string
}

//////////
//■[ ServerActions ]
export interface SignFormState {
    success:boolean
    errMsg:string
}
