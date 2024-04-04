'use server'

import { cookies } from 'next/headers'

export async function create() {
  console.log('create');
  cookies().set('cartId', 'cart.id')
}
