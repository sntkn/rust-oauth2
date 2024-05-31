import { NextResponse, NextRequest } from 'next/server';
import { session } from '../../../../lib/session'
import { Article, Token } from '../../../../entity'

export async function GET(req: NextRequest, context: { params: { id: string } }) {
  console.log("=============cyns====== GET aritcle")

  const id = context.params.id
  const token: Token = await session().get('token');
  const res = await fetch(`http://localhost:3001/articles/${id}`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token.accessToken}`
    },
  })
  const article: Article = await res.json()

  return NextResponse.json(article)
}

export async function PUT(req: NextRequest, context: { params: { id: string } }) {
  const id = context.params.id
  const data = await req.json();
  const token: Token = await session().get('token');

  const res = await fetch(`http://localhost:3001/articles/${id}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token.accessToken}`
    },
    body: JSON.stringify(data),
  })
  const article: Article = await res.json()

  return NextResponse.json(article)
}