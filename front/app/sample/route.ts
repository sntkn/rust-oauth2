import { NextResponse, NextRequest } from 'next/server';
import { cookies } from 'next/headers';
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  console.log(searchParams)
  cookies().set('cartId', 'cart.id')
  return NextResponse.redirect('http://localhost:8000');
}

