import { NextResponse, NextRequest } from 'next/server';
//import { cookies } from 'next/headers'

type Token = {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
}

export async function POST(req: NextRequest) {
  //cookies().set('access_token', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', { expires: Date.now() + 1000 })
  const data = await req.json();
  const code = data.code;

  const res = await fetch('http://localhost:3000/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      code,
    })
  })

  const token: Token = await res.json()
  console.log(token)

  // me (あとでどかす)
  const res2 = await fetch('http://localhost:3000/me', {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token.access_token}`
    },
  })
  const user = await res2.json()
  console.log(user)

  const response = NextResponse.json({ user })

  return response
}
