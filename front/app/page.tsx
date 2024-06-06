'use client'

import { useEffect, useState } from 'react'
import { Article } from '../entity'
import Link from 'next/link'

async function fetchArticles(): Promise<Article[]> {
  const res = await fetch('http://localhost:8000/api/fetchArticle', {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
    cache: 'no-cache',
  })

  return await res.json()
}

export default function Home() {

  const [articles, setArticles] = useState<Article[]>([]);

  useEffect(() => {
    (async () => {
      const res: Article[] = await fetchArticles()
      if (res.length) {
        setArticles(res)
      }
    })()
  }, [])

  return (
    <div>
      <p>App</p>
      <ul>
        {articles.map(article =>
          <>
            <li key={article.id}>
              <Link href={`/article/${article.id}`}>
                <strong>{article.title}</strong>
              </Link>
            </li >
          </>
        )}
      </ul>
    </div >
  )
}
