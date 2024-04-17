import Link from 'next/link'
import { User } from '../entity'
import { session } from '../lib/session'

const Header = async () => {
  const user: User = await session().get('user')
  return (
    <header className="bg-blue-500 p-4">
      <div className="container mx-auto">
        <nav className="flex items-center justify-between">
          <Link href="/" className="text-white text-2xl font-bold">
            My App
          </Link>
          <ul className="flex space-x-4">
            <li>
              {!user && (
                <Link
                  href="http://localhost:3000/authorize?response_type=code&client_id=550e8400-e29b-41d4-a716-446655440000&scope=read&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcallback&state=ok"
                  className="text-white hover:underline"
                >
                  Login
                </Link>
              )}
              {user && (
                <>
                  <span>ようこそ {user.name} さん</span>
                  <Link
                    href="http://localhost/"
                    className="text-white hover:underline"
                  >
                    ログアウト
                  </Link>
                </>
              )}
            </li>
            <li>
              <Link href="/contact" className="text-white hover:underline">
                Contact
              </Link>
            </li>
          </ul>
        </nav>
      </div>
    </header>
  )
}

export default Header
