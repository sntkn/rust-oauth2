import { Article, User } from '../../../entity'
import { getUser } from '../../../lib/serverActions'
import Link from 'next/link';

async function get(id: string): Promise<Article | null> {
  const res = await fetch(`http://localhost:8000/api/articles/${id}`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
    cache: 'no-cache',
  })


  if (!res.ok) {
    return null
  }

  return await res.json()
}

export default async function UserPage(context: { params: { id: string } }) {
  const id = context.params.id
  if (typeof id !== 'string') {
    return (<div>404 Not Found.</div>)
  }


  const article: Article | null = await get(id)
  if (!article) {
    return (<div>404 Not Found</div>)
  }

  const user: User = await getUser()

  const mine = user?.id === article.author_id

  return (
    <div className="max-w-xl mx-auto p-6 bg-white rounded-lg shadow-md my-6">
      {mine && (
        <div className="flex justify-end">
          <Link href={`./${article.id}/edit`} className="bg-blue-500 text-white font-bold py-2 px-4 rounded-full">Edit</Link>
        </div>
      )
      }
      <h1 className="text-2xl font-bold mb-4 text-black">記事</h1>
      <div>
        <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="title">タイトル</label>
        <p
          id="title"
          className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring focus:ring-blue-200 focus:border-blue-500 text-black"
        >{article.title}</p>
      </div>
      <div>
        <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="content">内容</label>
        <p
          id="content"
          className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring focus:ring-blue-200 focus:border-blue-500 text-black"
        >{article.content}</p>
      </div>
    </div >
  )
}
