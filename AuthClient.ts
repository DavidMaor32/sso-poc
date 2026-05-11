import jwt, { SignOptions } from "jsonwebtoken";
import { CallbackExtras, CallbackParamsType, Client, IdTokenClaims, Issuer, OpenIDCallbackChecks } from "openid-client";

export interface AuthClientConfig {
    jwtSecret: string;
    issuerURL: string;
    clientID: string;
    clientSecret: string;
    cbURL: string;
}

export type Payload = Pick<IdTokenClaims, 'preffered_name' | 'name' | 'exp' | 'iat'>;

export class AuthClient {
    private _client?: Client;

    constructor(private config: AuthClientConfig) {}

    start = async () => {
        const recievedIssuer = await Issuer.discover(this.config.issuerURL);
        this._client = new recievedIssuer.Client({
            client_id: this.config.clientID,
            client_secret: this.config.clientSecret,
            clockTolerance: 10
        });


    };

    sign = (payload: {}, options?: SignOptions) => 
        jwt.sign(payload, this.config.jwtSecret, options);

    isValidToken = (token: any) => {
        try {
            jwt.verify(token, this.config.jwtSecret);

            return true;
        } catch (e) {
            const error = e as Error;
            throw new Error(error.message);
        }
    };

    callback = async (
        parameters: CallbackParamsType,
        checks?: OpenIDCallbackChecks,
        extras?: CallbackExtras
    ): Promise<Payload> =>  {
        const tokenSet = await this.client().callback(
            this.config.cbURL,
            parameters,
            checks,
            extras
        );

        const accessToken = tokenSet.access_token;

        if(!accessToken) {
            throw new Error("unauthorized error");
        }

        // const res = await this.client().introspect(accessToken);

        // if(!res.active || tokenSet.expired()) {
        //     console.log(`Token invalid - occured in SSO comeback`);
        //     throw new Error('unauthorized Error');
        // }

        const { preffered_name, exp, name, iat } = tokenSet.claims();
        
        const payload = {
            preffered_name,
            name,
            exp,
            iat
        }

        return payload;
    }

    getAuthorizationUrl = () => {
        return this.client().authorizationUrl({
            redirect_uri: this.config.cbURL,
            scope: 'openid profile email'
        });
    };

    private client = () => {
        if (!this._client) {
            throw new Error('OpenId not initialized');
        }

        return this._client;
    }
}
