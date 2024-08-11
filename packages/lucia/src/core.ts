import { TimeSpan, createDate, isWithinExpirationDate } from "oslo";
import { CookieController } from "oslo/cookie";
import { sign, verify, SignOptions, VerifyOptions } from "jsonwebtoken";

import type { Cookie } from "oslo/cookie";
import type { Adapter } from "./database.js";
import type {
	RegisteredDatabaseSessionAttributes,
	RegisteredDatabaseUserAttributes,
	RegisteredLucia,
	UserId
} from "./index.js";
import { CookieAttributes } from "oslo/cookie";
import { generateIdFromEntropySize } from "./crypto.js";

type SessionAttributes = RegisteredLucia extends Lucia<infer _SessionAttributes, any>
	? _SessionAttributes
	: {};

type UserAttributes = RegisteredLucia extends Lucia<any, infer _UserAttributes>
	? _UserAttributes
	: {};

export interface Session extends SessionAttributes {
	id: string;
	expiresAt: Date;
	fresh: boolean;
	userId: UserId;
}

export interface JWTOptions {
	id: string;
	signOptions: SignOptions;
	verifyOptions: VerifyOptions;
	user: Record<string, any>;
}

export interface User extends UserAttributes {
	id: UserId;
}

export class Lucia<
	_SessionAttributes extends {} = Record<never, never>,
	_UserAttributes extends {} = Record<never, never>,
	_JWTTokens extends {} = Record<never, never>
> {
	private adapter: Adapter | null;
	private sessionExpiresIn: TimeSpan | null;
	private sessionCookieController: CookieController;
	private useJWT: boolean | null;
	private jwtSecret: string | null;
	private jwtOptions: JWTOptions | null;

	private getSessionAttributes: (
		databaseSessionAttributes: RegisteredDatabaseSessionAttributes
	) => _SessionAttributes;

	private getUserAttributes: (
		databaseUserAttributes: RegisteredDatabaseUserAttributes
	) => _UserAttributes;

	public createJWTToken: (options?: SignOptions, user?: Record<string, any>) => _JWTTokens;

	public verifyJWTToken: (token?: string, secret?: string) => _JWTTokens;

	public readonly sessionCookieName: string;

	constructor(
		adapter?: Adapter,
		options?: {
			sessionExpiresIn?: TimeSpan;
			sessionCookie?: SessionCookieOptions;
			useJWT?: boolean;
			jwtSecret?: string;
			jwtOptions?: JWTOptions;
			getSessionAttributes?: (
				databaseSessionAttributes: RegisteredDatabaseSessionAttributes
			) => _SessionAttributes;
			getUserAttributes?: (
				databaseUserAttributes: RegisteredDatabaseUserAttributes
			) => _UserAttributes;
		}
	) {
		this.adapter = adapter ?? null;
		this.useJWT = options?.useJWT ?? false;
		this.jwtSecret = options?.jwtSecret ?? null;
		this.jwtOptions = options?.jwtOptions ?? null;

		// we have to use `any` here since TS can't do conditional return types
		this.getUserAttributes = (databaseUserAttributes): any => {
			if (options && options.getUserAttributes) {
				return options.getUserAttributes(databaseUserAttributes);
			}
			return {};
		};

		this.getSessionAttributes = (databaseSessionAttributes): any => {
			if (options && options.getSessionAttributes) {
				return options.getSessionAttributes(databaseSessionAttributes);
			}
			return {};
		};

		this.createJWTToken = (options?: SignOptions, user?: Record<string, any>): any => {
			try {
				if (this.useJWT && this.jwtSecret) {
					if (options && user) {
						const token = sign(user, this.jwtSecret, options);
						return {
							token,
							expiresAt: options.expiresIn
						};
					}
					if (this.jwtOptions) {
						const token = sign(this.jwtOptions.user, this.jwtSecret, this.jwtOptions.signOptions);
						return {
							token,
							expiresAt: this.jwtOptions.signOptions.expiresIn
						};
					}
				}
				throw new Error("Creating Token Failed.");
			} catch (error) {
				throw new Error("Creating Token Failed.");
			}
		};

		this.verifyJWTToken = (token?: string, secret?: string): any => {
			try {
				if (this.useJWT && this.jwtSecret) {
					if (token && secret) {
						const decoded = verify(token, secret);
						return decoded;
					}
					if (this.jwtOptions) {
						const decoded = verify(
							this.jwtOptions.id,
							this.jwtSecret,
							this.jwtOptions.verifyOptions
						);
						return decoded;
					}
				}
				throw new Error("Verifying Token Failed.");
			} catch (error) {
				throw new Error("Verifying Token Failed.");
			}
		};

		this.sessionExpiresIn = options?.sessionExpiresIn ?? new TimeSpan(30, "d");
		this.sessionCookieName = options?.sessionCookie?.name ?? "auth_session";
		let sessionCookieExpiresIn = this.sessionExpiresIn;
		if (options?.sessionCookie?.expires === false) {
			sessionCookieExpiresIn = new TimeSpan(365 * 2, "d");
		}
		const baseSessionCookieAttributes: CookieAttributes = {
			httpOnly: true,
			secure: true,
			sameSite: "lax",
			path: "/",
			...options?.sessionCookie?.attributes
		};
		this.sessionCookieController = new CookieController(
			this.sessionCookieName,
			baseSessionCookieAttributes,
			{
				expiresIn: sessionCookieExpiresIn
			}
		);
	}

	public async getUserSessions(userId: UserId): Promise<Session[]> {
		if (!this.adapter) {
			throw new Error("No adapter provided.");
		}
		const databaseSessions = await this.adapter.getUserSessions(userId);
		const sessions: Session[] = [];
		for (const databaseSession of databaseSessions) {
			if (!isWithinExpirationDate(databaseSession.expiresAt)) {
				continue;
			}
			sessions.push({
				id: databaseSession.id,
				expiresAt: databaseSession.expiresAt,
				userId: databaseSession.userId,
				fresh: false,
				...this.getSessionAttributes(databaseSession.attributes)
			});
		}
		return sessions;
	}

	public async validateSession(
		sessionId: string
	): Promise<{ user: User; session: Session } | { user: null; session: null }> {
		if (!this.adapter || !this.sessionExpiresIn) {
			throw new Error("No adapter provided.");
		}
		const [databaseSession, databaseUser] = await this.adapter.getSessionAndUser(sessionId);
		if (!databaseSession) {
			return { session: null, user: null };
		}
		if (!databaseUser) {
			await this.adapter.deleteSession(databaseSession.id);
			return { session: null, user: null };
		}
		if (!isWithinExpirationDate(databaseSession.expiresAt)) {
			await this.adapter.deleteSession(databaseSession.id);
			return { session: null, user: null };
		}
		const activePeriodExpirationDate = new Date(
			databaseSession.expiresAt.getTime() - this.sessionExpiresIn.milliseconds() / 2
		);
		const session: Session = {
			...this.getSessionAttributes(databaseSession.attributes),
			id: databaseSession.id,
			userId: databaseSession.userId,
			fresh: false,
			expiresAt: databaseSession.expiresAt
		};
		if (!isWithinExpirationDate(activePeriodExpirationDate)) {
			session.fresh = true;
			session.expiresAt = createDate(this.sessionExpiresIn);
			await this.adapter.updateSessionExpiration(databaseSession.id, session.expiresAt);
		}
		const user: User = {
			...this.getUserAttributes(databaseUser.attributes),
			id: databaseUser.id
		};
		return { user, session };
	}

	public async createSession(
		userId: UserId,
		attributes: RegisteredDatabaseSessionAttributes,
		options?: {
			sessionId?: string;
		}
	): Promise<Session> {
		if (!this.adapter || !this.sessionExpiresIn) {
			throw new Error("No adapter provided.");
		}
		const sessionId = options?.sessionId ?? generateIdFromEntropySize(25);
		const sessionExpiresAt = createDate(this.sessionExpiresIn);
		await this.adapter.setSession({
			id: sessionId,
			userId,
			expiresAt: sessionExpiresAt,
			attributes
		});
		const session: Session = {
			id: sessionId,
			userId,
			fresh: true,
			expiresAt: sessionExpiresAt,
			...this.getSessionAttributes(attributes)
		};
		return session;
	}

	public async invalidateSession(sessionId: string): Promise<void> {
		if (!this.adapter) {
			throw new Error("No adapter provided.");
		}
		await this.adapter.deleteSession(sessionId);
	}

	public async invalidateUserSessions(userId: UserId): Promise<void> {
		if (!this.adapter) {
			throw new Error("No adapter provided.");
		}
		await this.adapter.deleteUserSessions(userId);
	}

	public async deleteExpiredSessions(): Promise<void> {
		if (!this.adapter) {
			throw new Error("No adapter provided.");
		}
		await this.adapter.deleteExpiredSessions();
	}

	public readSessionCookie(cookieHeader: string): string | null {
		const sessionId = this.sessionCookieController.parse(cookieHeader);
		return sessionId;
	}

	public readBearerToken(authorizationHeader: string): string | null {
		const [authScheme, token] = authorizationHeader.split(" ") as [string, string | undefined];
		if (authScheme !== "Bearer") {
			return null;
		}
		return token ?? null;
	}

	public createSessionCookie(sessionId: string): Cookie {
		return this.sessionCookieController.createCookie(sessionId);
	}

	public createBlankSessionCookie(): Cookie {
		return this.sessionCookieController.createBlankCookie();
	}
}

export interface SessionCookieOptions {
	name?: string;
	expires?: boolean;
	attributes?: SessionCookieAttributesOptions;
}

export interface SessionCookieAttributesOptions {
	sameSite?: "lax" | "strict" | "none";
	domain?: string;
	path?: string;
	secure?: boolean;
}
