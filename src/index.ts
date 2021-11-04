import type WorkOS from '@workos-inc/node';
import type { Profile } from '@workos-inc/node';
import type { Request } from 'express';
import passport from 'passport-strategy';

export interface WorkOSStrategyOptions {
    workos: WorkOS;
    clientID: string;
}

export type WorkOSStrategyVerifierCallback<User> = (err?: Error, user?: User, status?: number) => void;

export type WorkOSStrategyVerifier<User> = (req: Request, accessToken: string, profile: Profile, callback: WorkOSStrategyVerifierCallback<User>) => void;

export class WorkOSStrategy<User = any> extends passport.Strategy {
    private options: WorkOSStrategyOptions;
    private verifier: WorkOSStrategyVerifier<User>;

    constructor(options: WorkOSStrategyOptions, verifier: WorkOSStrategyVerifier<User>) {
        super();
        this.options = options;
        this.verifier = verifier;
    }

    async authenticate(req: Request): Promise<void> {
        try {
            const code = req.query.code as (string | undefined);

            if (!code) {
                this.fail(401);
                return;
            }

            const { access_token: accessToken, profile } = await this.options.workos.sso.getProfileAndToken({
                code,
                clientID: this.options.clientID,
            });

            this.verifier(req, accessToken, profile, (err?: Error, user?: User, status?: number) => {
                if (err) {
                    this.error(err);
                } else if (!user) {
                    this.fail(status ?? 401);
                } else {
                    this.success(user);
                }
            });
        } catch (err: any) {
            this.error(err);
        }
    }
}
