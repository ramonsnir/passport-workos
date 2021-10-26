import type WorkOS from '@workos-inc/node';
import type { Profile } from '@workos-inc/node';
import type { Request } from 'express';
import passport from 'passport-strategy';

export interface WorkOSStrategyOptions {
    workos: WorkOS;
    clientID: string;
}

export type WorkOSStrategyVerifierCallback<User> = WorkOSStrategy<User>['verified'];

export type WorkOSStrategyVerifier<User> = (req: Request, profile: Profile, callback: WorkOSStrategyVerifierCallback<User>) => void;

export class WorkOSStrategy<User = any> extends passport.Strategy {
    _options: WorkOSStrategyOptions;
    _verifier: WorkOSStrategyVerifier<User>;

    constructor(options: WorkOSStrategyOptions, verifier: WorkOSStrategyVerifier<User>) {
        super();
        this._options = options;
        this._verifier = verifier;
    }

    verified = (err?: Error, user?: User, status?: number) => {
        if (err) {
            this.error(err);
        } else if (!user) {
            this.fail(status ?? 401);
        } else {
            this.success(user);
        }
    };

    async authenticate(req: Request): Promise<void> {
        const code = req.query.code as (string | undefined);

        if (!code) {
            this.fail(401);
            return;
        }

        const { profile } = await this._options.workos.sso.getProfileAndToken({
            code,
            clientID: this._options.clientID,
        });

        this._verifier(req, profile, this.verified);
    }
}
