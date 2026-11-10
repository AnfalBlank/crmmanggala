import { NextResponse, type NextRequest } from "next/server";
import { eq } from "drizzle-orm";

import { db } from "@/db";
import { sessions } from "@/db/schema";

const PUBLIC_PATHS = ["/login", "/api/auth/login", "/_next", "/favicon.ico"];
const SESSION_COOKIE = "manggala_session";

// The cookie alone is not proof of login: look the session up and check it hasn't expired.
async function isValidSession(sessionId: string | undefined) {
  if (!sessionId) return false;
  try {
    const session = await db.query.sessions.findFirst({
      where: eq(sessions.id, sessionId),
    });
    if (!session) return false;
    if (session.expiresAt && new Date(session.expiresAt) < new Date()) return false;
    return true;
  } catch {
    return false;
  }
}

export async function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const isPublic = PUBLIC_PATHS.some((path) => pathname === path || pathname.startsWith(path));
  const sessionId = request.cookies.get(SESSION_COOKIE)?.value;
  const hasSession = await isValidSession(sessionId);

  if (!hasSession && !isPublic) {
    let response: NextResponse;
    if (pathname.startsWith("/api/")) {
      response = NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    } else {
      const url = new URL("/login", request.url);
      url.searchParams.set("next", pathname);
      response = NextResponse.redirect(url);
    }
    if (sessionId) response.cookies.delete(SESSION_COOKIE);
    return response;
  }

  if (hasSession && pathname === "/login") {
    return NextResponse.redirect(new URL("/", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!.*\\..*|_next).*)"],
};
