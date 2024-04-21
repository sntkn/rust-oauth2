'use server'
import { session } from '../lib/session'
import { Token, User } from '../entity'

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