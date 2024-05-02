import { NextResponse, NextRequest } from 'next/server';
import { User, Token } from '../../../entity'
import { session } from '../../../lib/session'

export async function GET(req: NextRequest) {
  const token = req.headers.get('Authorization')?.split(' ')[1];

  const res = await fetch('http://localhost:3000/me', {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
  })
  const user: User = await res.json()

  return NextResponse.json(user)
}

export async function PUT(req: NextRequest) {
  const data = await req.json();
  const token: Token = await session().get('token');

  const res = await fetch('http://localhost:3001/user', {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token.accessToken}`
    },
    body: JSON.stringify(data),
  })
  const user: User = await res.json()
  if (user) {
    session().set('user', user);
  }

  return NextResponse.json(user)
}
