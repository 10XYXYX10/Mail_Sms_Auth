import { IconHome } from '@tabler/icons-react'
import Link from 'next/link'
 
export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-100">
        <div className="p-4 space-y-4 bg-white rounded shadow-md">
            <p className="text-lg font-semibold text-red-600">404 Not Found</p>
            <p className="text-gray-500">🙇このURLページは存在しません🙇</p>
            <div>
                <Link
                    href="/" 
                    className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-blue-600 hover:text-blue-700 rounded-lg bg-blue-50 hover:bg-blue-100 active:bg-blue-200"
                >
                    <IconHome/>Return Home
                </Link>
            </div>
        </div>
    </div>
  )
}