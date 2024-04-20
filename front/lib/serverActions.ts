'use server'
import { session } from '../lib/session'
import { Token, User } from '../entity'

export const handleLogout = async () => {
  const token: Token = await session().get('token')
  if (!token) {
    await session().set('user', null)
    return;
  }

  const res = await fetch('http://localhost:8000/api/signOut', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token.accessToken}`,
    },
    cache: 'no-cache',
  })

  console.log(res)

  await session().set('user', null)
  await session().set('token', null)

  const json = await res.json()
  console.log(json)
}

export const getUser = async (): Promise<User> => {
  return await session().get('user')
}