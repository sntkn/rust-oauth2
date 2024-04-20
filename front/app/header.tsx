'use client'

import Link from 'next/link'
import { useEffect, useState } from 'react'
import { User, Token } from '../entity'

import { handleLogout, getUser } from '../lib/serverActions';
const Header = () => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  useEffect(() => {
    (async () => {
      const user: User = await getUser()
      console.log("User -----------")
      console.log(user)
      if (user) {
        setUser(user)
      }
    })()
  }, [])


  useEffect(() => {
    // userの中身が変わるたびにisLoggedInを更新
    setIsLoggedIn(!!user);
  }, [user])

  const handleLogoutClick = () => {
    handleLogout()
  }


  return (
    <header className="bg-blue-500 p-4">
      <div className="container mx-auto">
        <nav className="flex items-center justify-between">
          <Link href="/" className="text-white text-2xl font-bold">
            My App
          </Link>
          <ul className="flex space-x-4">
            <li>
              {!isLoggedIn && (
                <Link
                  href="http://localhost:3000/authorize?response_type=code&client_id=550e8400-e29b-41d4-a716-446655440000&scope=read&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcallback&state=ok"
                  className="text-white hover:underline"
                >
                  Login
                </Link>
              )}
              {isLoggedIn && user && (
                <>
                  <span>ようこそ {user.name} さん</span>
                  <span
                    onClick={() => handleLogoutClick()}
                    className="text-white hover:underline"
                  >
                    ログアウト
                  </span>
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
