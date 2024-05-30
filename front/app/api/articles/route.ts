import { NextResponse, NextRequest } from 'next/server';
import { Article, Token } from '../../../entity'
import { session } from '../../../lib/session'

export async function POST(req: NextRequest) {
  const data = await req.json();
  const token: Token = await session().get('token');

  const res = await fetch('http://localhost:3001/articles', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token.accessToken}`,
    },
    body: JSON.stringify({
      title: data.title,
      content: data.content,
    }),
  })
  const article: Article = await res.json()

  return NextResponse.json(article)
}

