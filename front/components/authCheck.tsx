'use client'

import { ReactNode, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { getUser } from '../lib/serverActions'


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
    return <div>Loading...</div>;
  }

  return children;
}

export default AuthCheck;
