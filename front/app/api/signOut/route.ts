import { NextResponse, NextRequest } from 'next/server';

export async function GET(req: NextRequest) {
  const token = req.headers.get('Authorization')?.split(' ')[1];

  const res = await fetch('http://localhost:3000/signOut', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
  })


  return NextResponse.json({ result: true })
}
