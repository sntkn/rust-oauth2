export type User = {
  id: string;
  name: string;
  email: string;
}

export type Token = {
  accessToken: string
  refreshToken: string
  expiresIn: number
}