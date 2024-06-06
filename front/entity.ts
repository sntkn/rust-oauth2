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

export type Article = {
  id: string
  title: string
  content: string
  author_id: string
  publishedAt: Date | null
  deletedAt: Date | null
  createdAt: Date
  updatedAt: Date
}
