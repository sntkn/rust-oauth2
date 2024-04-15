import { NextResponse, NextRequest } from 'next/server';
import { User } from '../../../entity'

export async function GET(req: NextRequest) {
  const token = req.headers.get('Authorization')?.split(' ')[1];
  console.log(token);

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
