# Token Manager

This package is for creating access token or refresh token.

## How to use

### 1. Install

```shell
npm install @meigetsunet/idframework-token
```

This package is contained type data so you need not install it separately.

### 2. Create IO Manager

This package is not contained record io process so you need writing it interface `IOManagerBase` implemented.

Please implement this code according to your environment.

```typescript
import { TokenInformation, TokenGenInformation, IOManagerBase } from '@meigetsunet/idframework-token';

export class IOManager implements IOManagerBase {
    private Tokens: { [key: string]: TokenGenInformation<string> } = {};
    async write(data: TokenGenInformation<string>): Promise<void> {
        this.Tokens[data.token] = data;
        return Promise.resolve();
    }
    async read(token: string): Promise<TokenInformation<string> | null> {
        return Promise.resolve(this.Tokens[token] || null);
    }
    async remove(token: string): Promise<void> {
        delete this.Tokens[token];
        return Promise.resolve();
    }
}
```

If your code is JavaScript, Import is only `IOManagerBase` because `TokenInformation` and `TokenGenInformation` are value types.

### 3. Init TokenManager

```typescript
import TokenManager from '@meigetsunet/idframework-token';
import { IOManager } from './IOManager';

// Default config and supported method
const AccessToken = new TokenManager(new IOManager(), 'md5');

// Token length customization
const AccessToken = new TokenManager(new IOManager(), 'md5', { length: 64 });

// Set salt in hash base value
const AccessToken = new TokenManager(new IOManager(), 'md5', { salt: 'my-salt' });

// Use custom hash function
const AccessToken = new TokenManager(new IOManager(), (value: string) => value);
```

#### Description of `constructor` arguments

|Argument|Description|Type|
|----|----|----|
|IO|Your IO Manager|a class implemented the interface `IOManagerBase`|
|HashedAlgorithmMethod|A method for hashing token|`string` or your custom hash method|
|TokenConfig|Token generation and hash config|`{ length: number, salt: string \| undefined }`|

TokenConfig is set to `{ length: 32 }` as the initial value.

### 4. Call member method of `TokenManager`

`TokenManager` is contained methods `create`, `get` and `revoke`.

#### `create`

This method is to create tokens.

|Argument|Description|Type|
|----|----|----|
|id|Account ID|`string`|
|scopes|Scopes linked to token|`string[]`|
|ExpireDate|Expire date of token|`Date`|

Return value is a issued token.

#### `get`

This method is to read token linked information.

|Argument|Description|Type|
|----|----|----|
|token|Token string|`string`|

Return value

|Pattern|Value|
|----|----|
|Token is not found|null|
|Token is expired|null|
|OK|`{ expires_at: Date, linked_id: string, scopes: string[] }`|

##### Parameter description

|Parameter|Description|
|----|----|
|expires_at|Expire date of token|
|linked_id|ID linked in token|
|scopes|Scopes linked in token|

#### `revoke`

This method is to revoke token.

This method returns no value so if you need to return any errors, please throw error.

|Argument|Description|Type|
|----|----|----|
|token|Token string|`string`|

## Default supported methods

|Hash Type|Value of constructor second argument|
|----|----|
|Plain Text|`plain`|
|MD5|`md5`|
|SHA-1|`sha1`|
|SHA-256|`sha256`|
|SHA-384|`sha384`|
|SHA-512|`sha512`|

## License

Copyright 2024 Meigetsu.
