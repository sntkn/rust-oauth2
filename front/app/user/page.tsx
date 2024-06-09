'use client'

import { useEffect, useState } from 'react'
import { User } from '@/entity'
import { getUser } from '@/lib/serverActions';
import AuthCheck from '@/components/authCheck'


async function fetchUer(name: string): Promise<User> {
  const res = await fetch('http://localhost:8000/api/fetchUser', {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ name }),
    cache: 'no-cache',
  })

  return await res.json()
}

export default function AuthenticatedPage() {
  const [user, setUser] = useState<User | null>(null);
  const [name, setName] = useState('');

  useEffect(() => {
    (async () => {
      const user: User = await getUser()
      if (user) {
        setUser(user)
        console.log(user)
        setName(user.name)
      }
    })()
  }, [])

  const handleSubmit = (e: React.SyntheticEvent) => {
    e.preventDefault();
    (async () => {
      const res = await fetchUer(name);
    })()
  }

  return (
    <AuthCheck>
      <div>
        <h1>ユーザー情報</h1>
        <form onSubmit={handleSubmit}>
          <input
            className='text-black'
            value={name}
            onChange={(e) => setName(e.target.value)}
          /><br />
          <button type="submit">更新</button>
        </form>
      </div>
    </AuthCheck>
  )
}
