'use client'

import { useState, useEffect } from 'react'
import { useParams } from 'next/navigation';
import { Article } from '../../../../entity'
import AuthCheck from '../../../../components/authCheck'


async function update(id: string, title: string, content: string): Promise<Article> {
  const res = await fetch(`http://localhost:8000/api/articles/${id}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ title, content }),
    cache: 'no-cache',
  })

  return await res.json()
}

async function get(id: string): Promise<Article> {
  const res = await fetch(`http://localhost:8000/api/articles/${id}`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
    cache: 'no-cache',
  })

  return await res.json()
}

export default function AuthenticatedPage() {
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

  const handleSubmit = (e: React.SyntheticEvent) => {
    e.preventDefault();
    (async () => {
      const res = await update(id, title, content);
    })()
  }

  return (
    <AuthCheck>
      <div className="max-w-xl mx-auto p-6 bg-white rounded-lg shadow-md my-6">
        <h1 className="text-2xl font-bold mb-4 text-black">編集</h1>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="title">タイトル</label>
            <input
              id="title"
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring focus:ring-blue-200 focus:border-blue-500 text-black"
              onChange={(e) => setTitle(e.target.value)}
              value={title}
            />
          </div>
          <div>
            <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="content">内容</label>
            <textarea
              id="content"
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring focus:ring-blue-200 focus:border-blue-500 text-black"
              rows={10}
              onChange={(e) => setContent(e.target.value)}
            >{content}</textarea>
          </div>
          <div>
            <button type="submit" className="w-full bg-blue-500 text-white font-bold py-2 px-4 rounded-md hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
              保存する
            </button>
          </div>
        </form >
      </div >
    </AuthCheck>
  )
}
