import * as crypto from 'crypto-js';
import { generate } from 'randomstring';
export const SupportedHashMethods = {
    plain: (text: string) => text,
    md5: (text: string) => crypto.MD5(text).toString(crypto.enc.Hex),
    sha1: (text: string) => crypto.SHA1(text).toString(crypto.enc.Hex),
    sha256: (text: string) => crypto.SHA256(text).toString(crypto.enc.Hex),
    sha384: (text: string) => crypto.SHA384(text).toString(crypto.enc.Hex),
    sha512: (text: string) => crypto.SHA512(text).toString(crypto.enc.Hex),
};

export type TokenInformation<ScopeDataType> = {
    expires_date: Date;
    linked_id: string;
    scopes: ScopeDataType;
};

export type TokenGenInformation<ScopeDataType> = TokenInformation<ScopeDataType> & {
    token: string;
};

export abstract class IOManagerBase {
    abstract write(data: TokenGenInformation<string>): Promise<void>;
    abstract read(token: string): Promise<TokenInformation<string> | null>;
    abstract remove(token: string): Promise<void>;
}

export default class TokenManager {
    private Method: (text: string) => string;
    constructor(
        private IO: IOManagerBase,
        HashedAlgorithmMethod: string | ((text: string) => string),
        private TokenConfig: { length: number; salt?: string } = { length: 32 }
    ) {
        if (typeof HashedAlgorithmMethod === 'string') {
            const l_HashMethodName = HashedAlgorithmMethod.toLowerCase();
            if (!SupportedHashMethods[l_HashMethodName]) throw new Error('Hash method not supported');
            this.Method = SupportedHashMethods[l_HashMethodName];
        } else this.Method = HashedAlgorithmMethod;
    }
    protected async CreateTokenText(): Promise<string> {
        const TokenText = generate({ length: this.TokenConfig.length, charset: 'alphanumeric' });
        const TokenGetResult = await this.get(TokenText);
        return TokenGetResult == null ? TokenText : this.CreateTokenText();
    }
    public async create(
        id: string,
        scopes: string[],
        ExpireDate: Date
    ): Promise<{ token: string; expires_at: Date }> {
        const TokenText = await this.CreateTokenText();
        await this.IO.write({
            token: this.Method(this.TokenConfig.salt == null ? TokenText : `${this.TokenConfig.salt}${TokenText}`),
            expires_date: ExpireDate,
            linked_id: id,
            scopes: scopes.join(','),
        });
        return {
            token: TokenText,
            expires_at: ExpireDate,
        };
    }
    public async get(token: string): Promise<TokenInformation<string[]> | null> {
        const tokenData = await this.IO.read(
            this.Method(this.TokenConfig.salt == null ? token : `${this.TokenConfig.salt}${token}`)
        ).then(data => {
            if (data == null) return null;
            return {
                expires_date: data.expires_date,
                linked_id: data.linked_id,
                scopes: data.scopes.split(','),
            };
        });
        if (tokenData == null) return null;
        if (tokenData.expires_date.getTime() < Date.now()) {
            await this.revoke(token);
            return null;
        }
        return tokenData;
    }
    public async revoke(token: string) {
        await this.IO.remove(this.Method(this.TokenConfig.salt == null ? token : `${this.TokenConfig.salt}${token}`));
    }
}
