'use client'

import { useEffect, useState } from 'react'
import { Article } from '../entity'

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
      {articles.map(article => <li key={article.id}>title:{article.title} / content:{article.content}</li>)}
    </div>
  )
}
