import { NextResponse, NextRequest } from 'next/server';
import { Article } from '../../../entity'

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

