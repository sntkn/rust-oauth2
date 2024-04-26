import { NextResponse, NextRequest } from 'next/server';

export async function POST(req: NextRequest) {
  const token = req.headers.get('Authorization')?.split(' ')[1];

  const res = await fetch('http://localhost:3000/signout', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
  })

  return NextResponse.json({ result: true })
}
