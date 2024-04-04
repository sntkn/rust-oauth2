import Link from 'next/link'

const Header = () => {
  return (
    <header className="bg-blue-500 p-4">
      <div className="container mx-auto">
        <nav className="flex items-center justify-between">
          <Link href="/" className="text-white text-2xl font-bold">
            My App
          </Link>
          <ul className="flex space-x-4">
            <li>
              <Link
                href="/authorize?response_type=code&client_id=550e8400-e29b-41d4-a716-446655440000&scope=read&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&state=ok"
                className="text-white hover:underline"
              >
                Login
              </Link>
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
