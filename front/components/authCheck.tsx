'use client'

import { ReactNode, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { getUser } from '@/lib/serverActions'


// 認証チェックコンポーネント
function AuthCheck({ children }: { children: ReactNode }) {
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    const handleRedirect = async () => {
      const token = await getUser();
      if (!token) {
        router.push('/');
      } else {
        // トークンの有効性を確認するためのAPI呼び出しをここで行うことができます
        setIsLoading(false);
      }
    };

    handleRedirect();
  }, [router]);

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-screen">
        <div className="w-16 h-16 border-4 border-gray-300 border-t-transparent border-solid rounded-full animate-spin"></div>
        <div className="mt-4 text-lg font-semibold text-gray-300">Loading...</div>
      </div>
    );
  }

  return children;
}

export default AuthCheck;
