import { NextResponse, NextRequest } from 'next/server';
//import { cookies } from 'next/headers'

type Token = {
  accessToken: string;
  refreshToken: string;
  expiry: number;
}

export async function POST(req: NextRequest) {
  //cookies().set('access_token', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', { expires: Date.now() + 1000 })
  const data = await req.json();
  const code = data.code;
  console.log(code);

  const response = new NextResponse(JSON.stringify({ result: true }))

  // Set a cookie
  response.cookies.set('myCookieName', 'some-value', { expires: Date.now() + 1000 })

  return response

  const res = await fetch('http://localhost:8080/token', {
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

  // TODO: setcookie
  //cookies().set('access_token', token.accessToken)

  return NextResponse.json({
    result: true
  })
}
