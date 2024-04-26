import { NextResponse, NextRequest } from 'next/server';
import { User } from '../../../entity'

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
  const token = req.headers.get('Authorization')?.split(' ')[1];

  const res = await fetch('http://localhost:3000/me', { // TODO API REQUEST
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify(data),
  })
  const user: User = await res.json()

  return NextResponse.json(user)
}
