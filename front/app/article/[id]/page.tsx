'use client'

import { useState, useEffect } from 'react'
import { useParams } from 'next/navigation';

import { Article } from '../../../entity'

async function get(id: string): Promise<Article> {
  console.log("=================== GET aritcle")
  const res = await fetch(`http://localhost:8000/api/articles/${id}`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
    cache: 'no-cache',
  })

  console.log(res)

  return await res.json()
}

export default function UserPage() {
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const { id } = useParams();
  if (typeof id !== 'string') {
    return (<div>404 Not Found.</div>)
  }


  useEffect(() => {
    (async () => {
      const article: Article = await get(id)
      if (article) {
        setTitle(article.title)
        setContent(article.content)
      }
    })()
  }, [])

  return (
    <div className="max-w-xl mx-auto p-6 bg-white rounded-lg shadow-md my-6">
      <h1 className="text-2xl font-bold mb-4 text-black">記事</h1>
      <div>
        <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="title">タイトル</label>
        <p
          id="title"
          className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring focus:ring-blue-200 focus:border-blue-500 text-black"
        >{title}</p>
      </div>
      <div>
        <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="content">内容</label>
        <p
          id="content"
          className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring focus:ring-blue-200 focus:border-blue-500 text-black"
        >{content}</p>
      </div>
    </div >
  )
}
