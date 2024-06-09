'use server'
import { session } from '@/lib/session'
import { Token, User } from '@/entity'

export const handleLogout = async (): Promise<Boolean> => {
  const token: Token = await session().get('token')
  if (!token) {
    await session().set('user', null)
    return true;
  }

  const res = await fetch('http://localhost:8000/api/signOut', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token.accessToken}`,
    },
    cache: 'no-cache',
  })

  await session().set('user', null)
  await session().set('token', null)

  const json = await res.json()
  return json.result === true
}

export const getUser = async (): Promise<User> => {
  return await session().get('user')
}

export const getToken = async (): Promise<Token | null> => {
  const token: Token = await session().get('token')
  if (!token) {
    //throw new Exception()
    return null
  }
  const currentTime = Math.floor(Date.now() / 1000); // 現在のUNIXタイムスタンプを取得
  if (token.expiresIn < currentTime) {
    const newToken: Token = await fetchToken(token.refreshToken)
    const user: User = await fetchUser(newToken.accessToken)
    await session().set('token', newToken);
    await session().set('user', user)

    return token
  }

  return token

}

async function fetchToken(refreshToken: string): Promise<Token> {
  const res = await fetch('http://localhost:8000/api/fetchTokenWithRefresh', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      refreshToken,
    }),
    cache: 'no-cache',
  })

  return await res.json()
}

async function fetchUser(token: string): Promise<User> {
  const res = await fetch('http://localhost:8000/api/fetchUser', {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    cache: 'no-cache',
  })

  return await res.json()
}