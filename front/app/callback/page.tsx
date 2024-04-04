type Result = {
  result: boolean
}

async function getData(code: string): Promise<Result> {
  // 認可コードが取得できた場合、アクセストークンの取得リクエストを送信
  const res = await fetch('http://localhost:3000/api/fetchToken', {
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
  const res = await getData(code)
  console.log(res)

  return (
    <div>
      <p>Processing...</p>
    </div>
  )
}
