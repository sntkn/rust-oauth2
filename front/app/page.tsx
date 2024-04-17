import { User, Token } from '../entity'
import { session } from '../lib/session'

export default async function Home() {
  const token: Token = await session().get('token')
  const user: User = await session().get('user')
  console.log(token)
  console.log(user)
  return (
    <div>
      <p>App</p>
    </div>
  )
}
