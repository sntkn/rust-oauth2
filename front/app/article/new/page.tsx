'use client'

import { useState } from 'react'
import { Article } from '../../../entity'
import { useRouter } from "next/navigation";
import AuthCheck from '../../../components/authCheck'

async function create(title: string, content: string): Promise<Article> {
  const res = await fetch('http://localhost:8000/api/articles', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ title, content }),
    cache: 'no-cache',
  })

  return await res.json()
}

export default function AuthenticatedPage() {
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const router = useRouter();

  const handleSubmit = (e: React.SyntheticEvent) => {
    e.preventDefault();
    (async () => {
      const res = await create(title, content);
      if (res) {
        router.push(`./article/{res.id}`);
      }
    })()
  }

  return (
    <AuthCheck>
      <div className="max-w-xl mx-auto p-6 bg-white rounded-lg shadow-md my-6">
        <h1 className="text-2xl font-bold mb-4 text-black">記事作成</h1>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="title">タイトル</label>
            <input
              id="title"
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring focus:ring-blue-200 focus:border-blue-500 text-black"
              onChange={(e) => setTitle(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="content">内容</label>
            <textarea
              id="content"
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring focus:ring-blue-200 focus:border-blue-500 text-black"
              rows={10}
              onChange={(e) => setContent(e.target.value)}
            ></textarea>
          </div>
          <div>
            <button type="submit" className="w-full bg-blue-500 text-white font-bold py-2 px-4 rounded-md hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
              記事を作成する
            </button>
          </div>
        </form >
      </div >
    </AuthCheck>
  )
}
