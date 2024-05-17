'use client'

import Link from 'next/link'
import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation';
import { User } from '../entity'
import { handleLogout, getUser } from '../lib/serverActions';

const Header = () => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [isMenuOpen, setIsMenuOpen] = useState(false); // メニューの開閉状態を管理
  const router = useRouter();

  useEffect(() => {
    (async () => {
      const user: User = await getUser()
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
    (async () => {
      const res = await handleLogout()
      if (res) {
        toggleMenu()
        setUser(null)
        setIsLoggedIn(!!user)
        router.push('/')
      }
    })()
  }

  const toggleMenu = () => {
    setIsMenuOpen(!isMenuOpen); // メニューの開閉状態を切り替える
  }

  return (
    <header className="bg-gray-800 text-white py-4 shadow-md flex items-center justify-between">
      <nav className="flex items-center">
        <div className="px-8">
          <Link href="/" className="text-white text-2xl font-bold px-8">
            My App
          </Link>
        </div>
      </nav>
      <div className="flex items-center">
        {!isLoggedIn && (
          <div className="px-8">
            <Link
              href="http://localhost:3000/authorize?response_type=code&client_id=550e8400-e29b-41d4-a716-446655440000&scope=read&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcallback&state=ok"
              className="text-white hover:underline"
            >
              Login
            </Link>
          </div>
        )}
        {isLoggedIn && user && (
          <div className="px-8">
            <span>ようこそ {user.name} さん</span>
          </div>
        )}
        <div className="px-8">
          <button onClick={toggleMenu} className="block">
            <svg className="fill-current text-white w-6 h-6" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20">
              <path d="M0 3h20v2H0V3zm0 6h20v2H0V9zm0 8h20v2H0v-2z" />
            </svg>
          </button>
        </div>
        <nav className={`absolute right-2 top-8 mt-4 bg-white rounded-lg shadow ${isMenuOpen ? "block" : "hidden"}`}>
          <ul className="flex flex-col text-gray-800 py-4">
            {isLoggedIn && user && (
              <li className="hover:bg-gray-300"><Link href="/user" onClick={toggleMenu} className="block px-8 py-2">User</Link></li>
            )}
            <li className="hover:bg-gray-300" onClick={toggleMenu}><a className="block px-8 py-2" href="/about">About</a></li>
            <li className="hover:bg-gray-300" onClick={toggleMenu}><a className="block px-8 py-2" href="/contact">Contact</a></li>
            {isLoggedIn && user && (
              <li className="hover:bg-gray-300">
                <button onClick={handleLogoutClick} className="block px-8 py-2">
                  Logout
                </button>
              </li>
            )}
          </ul>
        </nav>
      </div>
    </header>
  )
}

export default Header
