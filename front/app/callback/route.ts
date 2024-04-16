import { NextResponse, NextRequest } from 'next/server';
import { cookies } from 'next/headers';
import { User, Token } from '../../entity'

async function fetchToken(code: string): Promise<Token> {
  // 認可コードが取得できた場合、アクセストークンの取得リクエストを送信
  const res = await fetch('http://localhost:8000/api/fetchToken', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ code }),
    cache: 'no-cache',
  })

  return await res.json()
}

async function fetchUser(token: string): Promise<User> {
  // 認可コードが取得できた場合、アクセストークンの取得リクエストを送信
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

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const code = searchParams.get('code') ?? ''
  const token: Token = await fetchToken(code)
  const user: User = await fetchUser(token.accessToken)
  cookies().set('user', JSON.stringify(user))
  return NextResponse.redirect('http://localhost:8000');
}
