import { User } from '../../entity'

type Token = {
  access_token: string
  refresh_token: string
  expires_in: number
}

async function getData(code: string): Promise<User> {
  // 認可コードが取得できた場合、アクセストークンの取得リクエストを送信
  const res = await fetch('http://localhost:8000/api/fetchToken', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ code }),
    cache: 'no-cache',
  })

  return await res.json()
}

export default async function Callback({
  searchParams,
}: {
  searchParams: { [key: string]: string }
}) {
  // @see https://nextjs.org/docs/app/api-reference/file-conventions/page#searchparams-optional
  const code = searchParams.code
  const res: User = await getData(code)
  console.log(res)

  return (
    <div>
      <p>Processing...</p>
    </div>
  )
}
