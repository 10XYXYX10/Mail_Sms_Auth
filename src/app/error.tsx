'use client'
import { useEffect } from 'react';

export default function Error({
  error,
  reset,
}: {
  error: Error
  reset: () => void
}){

  useEffect(() => {
    if(process.env.NODE_ENV==='production'){
      console.log('Something went wrong!')
    }else{
      console.error(error)
    }
  }, [error])

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-100">
      <div className="p-4 space-y-4 bg-white rounded shadow-md">
        <p className="text-lg font-semibold text-red-600">Data fetching in server failed</p>
        <p className="text-gray-500">🙇データの取得に失敗しました。リロードしてもう一度お試し下さい🙇</p>
        <p className="text-sm text-gray-400">
          {process.env.NODE_ENV==='production'
            ?(
              'Something went wrong!'
            ):(
              error.message
            )
          }
        </p>
        <button onClick={() => reset()} className="px-4 py-2 text-white bg-blue-500 rounded hover:bg-blue-600">Try again</button>
      </div>
    </div>
  )
}
