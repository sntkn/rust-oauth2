import { NextResponse, NextRequest } from 'next/server';
import { Article, Token } from '@/entity'
import { getToken } from '@/lib/serverActions';

export async function POST(req: NextRequest) {
  const data = await req.json();
  const token: Token | null = await getToken()
  if (!token) {
    return null
  }

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

export async function GET(req: NextRequest) {
  const res = await fetch('http://localhost:3001/articles', {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
  })
  const articles: Article[] = await res.json()

  return NextResponse.json(articles)
}