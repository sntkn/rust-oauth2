import { User, Token } from '../../entity'

async function fetchToken(code: string): Promise<Token> {
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

async function fetchUser(token: string): Promise<User> {
  // 認可コードが取得できた場合、アクセストークンの取得リクエストを送信
  const res = await fetch('http://localhost:8000/api/fetchUser', {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
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
  const token: Token = await fetchToken(code)
  const user: User = await fetchUser(token.accessToken)

  return (
    <div>
      <p>Processing...</p>
      <dl>
        <dt>Accesstoken:</dt>
        <dd>{token.accessToken}</dd>
        <dt>RefreshToken</dt>
        <dd>{token.refreshToken}</dd>
      </dl>
      <h2>User</h2>
      <dl>
        <dt>ID</dt>
        <dd>{user.id}</dd>
        <dt>Name</dt>
        <dd>{user.name}</dd>
      </dl>
    </div>
  )
}
