import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server'
import { NextRequest, NextResponse } from 'next/server'
import { checkStrIsNotionId, getLastPartOfUrl } from '@/lib/utils'
import { idToUuid } from 'notion-utils'
import BLOG from './blog.config'

/**
 * Clerk 身份验证中间件
 */
export const config = {
  // 这里设置白名单，防止静态资源被拦截
  matcher: ['/((?!.*\\..*|_next|/sign-in|/auth).*)', '/', '/(api|trpc)(.*)']
}

const SITE_AUTH_PATH = '/site-auth'
const SITE_AUTH_COOKIE = 'notionnext_site_auth'
const SITE_AUTH_MAX_AGE = 60 * 60 * 24 * 7

const getSitePassword = () => process.env.SITE_PASSWORD || ''

const getSafeRedirectPath = (redirectTo: FormDataEntryValue | null) => {
  const value = typeof redirectTo === 'string' ? redirectTo : '/'
  if (value.startsWith('/') && !value.startsWith('//')) {
    return value
  }
  return '/'
}

const getSiteAuthToken = async (password: string) => {
  const data = new TextEncoder().encode(`notionnext-site-auth:${password}`)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(hashBuffer))
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('')
}

const buildLoginPage = (redirectTo: string, errorMessage = '') => `<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>请输入访问密码</title>
    <style>
      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        background: #f6f7f9;
        color: #111827;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      }
      .card {
        width: min(92vw, 380px);
        padding: 32px;
        border-radius: 18px;
        background: #fff;
        box-shadow: 0 20px 55px rgba(15, 23, 42, .12);
      }
      h1 {
        margin: 0 0 10px;
        font-size: 24px;
        line-height: 1.3;
      }
      p {
        margin: 0 0 22px;
        color: #6b7280;
        font-size: 14px;
      }
      input[type="password"] {
        width: 100%;
        height: 44px;
        padding: 0 12px;
        border: 1px solid #d1d5db;
        border-radius: 10px;
        font-size: 16px;
        outline: none;
      }
      input[type="password"]:focus {
        border-color: #111827;
      }
      button {
        width: 100%;
        height: 44px;
        margin-top: 14px;
        border: 0;
        border-radius: 10px;
        background: #111827;
        color: #fff;
        font-size: 16px;
        cursor: pointer;
      }
      .error {
        margin: 12px 0 0;
        color: #dc2626;
        font-size: 14px;
      }
    </style>
  </head>
  <body>
    <main class="card">
      <h1>请输入访问密码</h1>
      <p>该网站已开启私密访问。</p>
      <form method="post" action="${SITE_AUTH_PATH}">
        <input type="hidden" name="redirect" value="${redirectTo.replace(/"/g, '&quot;')}" />
        <input name="password" type="password" placeholder="访问密码" autofocus />
        <button type="submit">进入网站</button>
      </form>
      ${errorMessage ? `<div class="error">${errorMessage}</div>` : ''}
    </main>
  </body>
</html>`

const renderLoginPage = (req: NextRequest, errorMessage = '') => {
  const redirectTo = `${req.nextUrl.pathname}${req.nextUrl.search}`
  return new NextResponse(buildLoginPage(redirectTo, errorMessage), {
    status: 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store, max-age=0'
    }
  })
}

// 限制登录访问的路由
const isTenantRoute = createRouteMatcher([
  '/user/organization-selector(.*)',
  '/user/orgid/(.*)',
  '/dashboard',
  '/dashboard/(.*)'
])

// 限制权限访问的路由
const isTenantAdminRoute = createRouteMatcher([
  '/admin/(.*)/memberships',
  '/admin/(.*)/domain'
])

/**
 * 没有配置权限相关功能的返回
 * @param req
 * @param ev
 * @returns
 */
// eslint-disable-next-line @typescript-eslint/require-await, @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars
const noAuthMiddleware = async (req: NextRequest, ev: any) => {
  // 如果没有配置 Clerk 相关环境变量，返回一个默认响应或者继续处理请求
  if (BLOG['UUID_REDIRECT']) {
    let redirectJson: Record<string, string> = {}
    try {
      const response = await fetch(`${req.nextUrl.origin}/redirect.json`)
      if (response.ok) {
        redirectJson = (await response.json()) as Record<string, string>
      }
    } catch (err) {
      console.error('Error fetching static file:', err)
    }
    let lastPart = getLastPartOfUrl(req.nextUrl.pathname) as string
    if (checkStrIsNotionId(lastPart)) {
      lastPart = idToUuid(lastPart)
    }
    if (lastPart && redirectJson[lastPart]) {
      const redirectToUrl = req.nextUrl.clone()
      redirectToUrl.pathname = '/' + redirectJson[lastPart]
      console.log(
        `redirect from ${req.nextUrl.pathname} to ${redirectToUrl.pathname}`
      )
      return NextResponse.redirect(redirectToUrl, 308)
    }
  }
  return NextResponse.next()
}
/**
 * 鉴权中间件
 */
const authMiddleware = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY
  ? clerkMiddleware((auth, req) => {
      const { userId } = auth()
      // 处理 /dashboard 路由的登录保护
      if (isTenantRoute(req)) {
        if (!userId) {
          // 用户未登录，重定向到 /sign-in
          const url = new URL('/sign-in', req.url)
          url.searchParams.set('redirectTo', req.url) // 保存重定向目标
          return NextResponse.redirect(url)
        }
      }

      // 处理管理员相关权限保护
      if (isTenantAdminRoute(req)) {
        auth().protect(has => {
          return (
            has({ permission: 'org:sys_memberships:manage' }) ||
            has({ permission: 'org:sys_domains_manage' })
          )
        })
      }

      // 默认继续处理请求
      return NextResponse.next()
    })
  : noAuthMiddleware

const sitePasswordMiddleware = async (req: NextRequest, ev: any) => {
  const sitePassword = getSitePassword()

  // 未配置 SITE_PASSWORD 时，不开启全站密码保护
  if (!sitePassword) {
    return authMiddleware(req, ev)
  }

  if (req.nextUrl.pathname === SITE_AUTH_PATH) {
    if (req.method === 'POST') {
      const formData = await req.formData()
      const inputPassword = formData.get('password')
      const redirectPath = getSafeRedirectPath(formData.get('redirect'))

      if (inputPassword === sitePassword) {
        const redirectUrl = req.nextUrl.clone()
        redirectUrl.pathname = redirectPath
        redirectUrl.search = ''

        const response = NextResponse.redirect(redirectUrl, 303)
        response.cookies.set({
          name: SITE_AUTH_COOKIE,
          value: await getSiteAuthToken(sitePassword),
          httpOnly: true,
          sameSite: 'lax',
          secure: process.env.NODE_ENV === 'production',
          path: '/',
          maxAge: SITE_AUTH_MAX_AGE
        })
        return response
      }

      return renderLoginPage(req, '密码错误，请重试。')
    }

    return NextResponse.redirect(new URL('/', req.url), 303)
  }

  const expectedToken = await getSiteAuthToken(sitePassword)
  const currentToken = req.cookies.get(SITE_AUTH_COOKIE)?.value

  if (currentToken === expectedToken) {
    return authMiddleware(req, ev)
  }

  return renderLoginPage(req)
}

export default sitePasswordMiddleware
