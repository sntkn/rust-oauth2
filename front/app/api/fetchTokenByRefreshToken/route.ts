import { NextResponse, NextRequest } from 'next/server';
import { Token } from '@/entity'

type TokenResponse = {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
}

export async function POST(req: NextRequest) {
  const data = await req.json();
  const refreshToken = data.refreshToken;

  const res = await fetch('http://localhost:3000/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
    })
  })

  const tokenResponse: TokenResponse = await res.json()
  const token: Token = {
    accessToken: tokenResponse.access_token,
    refreshToken: tokenResponse.refresh_token,
    expiresIn: tokenResponse.expires_in,
  }

  return NextResponse.json(token)
}
