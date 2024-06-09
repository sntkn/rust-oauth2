import { NextResponse, NextRequest } from 'next/server';
import { Article, Token } from '../../../../entity'
import { getToken } from '../../../../lib/serverActions'

export async function GET(req: NextRequest, context: { params: { id: string } }) {

  const id = context.params.id
  const res = await fetch(`http://localhost:3001/articles/${id}`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
  })

  if (!res.ok) {
    return NextResponse.json({
      message: "Could not get article."
    }, {
      status: res.status,
    })
  }

  const article: Article = await res.json()

  return NextResponse.json(article)
}

export async function PUT(req: NextRequest, context: { params: { id: string } }) {
  const id = context.params.id
  const data = await req.json();
  const token: Token | null = await getToken()
  if (!token) {
    return null
  }

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