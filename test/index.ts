import { generate } from 'randomstring';
import TokenManager, { TokenInformation, TokenGenInformation, IOManagerBase, SupportedHashMethods } from '../src';
import { v4 as uuuidv4 } from 'uuid';

describe('SupportedHashMethods', () => {
    it('plain', () => {
        expect(SupportedHashMethods.plain('test')).toBe('test');
    });
    it('md5', () => {
        expect(SupportedHashMethods.md5('test')).toBe('098f6bcd4621d373cade4e832627b4f6');
    });
    it('sha1', () => {
        expect(SupportedHashMethods.sha1('test')).toBe('a94a8fe5ccb19ba61c4c0873d391e987982fbbd3');
    });
    it('sha256', () => {
        expect(SupportedHashMethods.sha256('test')).toBe(
            '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
        );
    });
    it('sha384', () => {
        expect(SupportedHashMethods.sha384('test')).toBe(
            '768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9'
        );
    });
    it('sha512', () => {
        expect(SupportedHashMethods.sha512('test')).toBe(
            'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff'
        );
    });
});

describe('TokenManager', () => {
    describe('No Salt', () => {
        it('init/no hashed method', () => {
            class IO implements IOManagerBase {
                write(data: TokenGenInformation<string>): Promise<void> {
                    return Promise.resolve();
                }
                read(token: string): Promise<TokenInformation<string> | null> {
                    return Promise.resolve(null);
                }
                remove(token: string): Promise<void> {
                    return Promise.resolve();
                }
            }
            expect(() => new TokenManager(new IO(), 'not_supported')).toThrow('Hash method not supported');
        });
        it('CreateTokenText', async () => {
            class IO {
                private callCount = 0;
                write(data: TokenGenInformation<string>): Promise<void> {
                    return Promise.resolve();
                }
                read(token: string): Promise<TokenInformation<string> | null> {
                    const Ret =
                        this.callCount++ === 0
                            ? {
                                  expires_at: new Date(Date.now() + 3600 * 1000),
                                  linked_id: 'test',
                                  scopes: 'user.read,user.write',
                              }
                            : null;
                    return Promise.resolve(Ret);
                }
                remove(token: string): Promise<void> {
                    return Promise.resolve();
                }
            }
            const TokenMgr = new TokenManager(new IO(), 'plain');
            const TokenText = await TokenMgr['CreateTokenText']();
            expect(TokenText).toMatch(/^[0-9A-Za-z]{32}$/);
        });
        describe('SupportedMethod', () => {
            it('create', async () => {
                const ID = uuuidv4();
                const ExpireDate = new Date(Date.now() + 3600 * 1000);
                class IO implements IOManagerBase {
                    write(data: TokenGenInformation<string>): Promise<void> {
                        expect(data.token).toMatch(/^[0-9A-Za-z]{32}$/);
                        const Expect = {
                            token: data.token, // mockしてないので、こうしないとテストが通らない
                            linked_id: ID,
                            scopes: 'user.read,user.write',
                            expires_at: ExpireDate,
                        };
                        expect(data).toStrictEqual(Expect);
                        return Promise.resolve();
                    }
                    read(token: string): Promise<TokenInformation<string> | null> {
                        return Promise.resolve(null);
                    }
                    remove(token: string): Promise<void> {
                        return Promise.resolve();
                    }
                }
                const TokenMgr = new TokenManager(new IO(), 'plain');
                const TokenText = await TokenMgr.create(ID, ['user.read', 'user.write'], ExpireDate);
                expect(TokenText).toMatch(/^[0-9A-Za-z]{32}$/);
            });
            it('get/ok', async () => {
                const ID = uuuidv4();
                const ExpireDate = new Date(Date.now() + 3600 * 1000);
                const TokenText = generate({ length: 32, charset: 'alphanumeric' });
                class IO implements IOManagerBase {
                    cache = [
                        {
                            token: SupportedHashMethods.sha256(TokenText),
                            expires_at: ExpireDate,
                            linked_id: ID,
                            scopes: 'user.read,user.write',
                        },
                    ];
                    write(data: TokenGenInformation<string>): Promise<void> {
                        return Promise.resolve();
                    }
                    read(token: string): Promise<TokenInformation<string> | null> {
                        return Promise.resolve(this.cache.find(v => v.token === token) || null);
                    }
                    remove(token: string): Promise<void> {
                        return Promise.resolve();
                    }
                }
                const TokenMgr = new TokenManager(new IO(), 'sha256');
                const TokenInfo = await TokenMgr.get(TokenText);
                const Expect = {
                    expires_at: ExpireDate,
                    linked_id: ID,
                    scopes: ['user.read', 'user.write'],
                };
                expect(TokenInfo).toStrictEqual(Expect);
            });
            it('get/expired', async () => {
                const ID = uuuidv4();
                const ExpireDate = new Date(Date.now() - 3600 * 1000);
                const TokenText = generate({ length: 32, charset: 'alphanumeric' });
                class IO implements IOManagerBase {
                    cache = [
                        {
                            token: SupportedHashMethods.sha256(TokenText),
                            expires_at: ExpireDate,
                            linked_id: ID,
                            scopes: 'user.read,user.write',
                        },
                    ];
                    write(data: TokenGenInformation<string>): Promise<void> {
                        return Promise.resolve();
                    }
                    read(token: string): Promise<TokenInformation<string> | null> {
                        return Promise.resolve(this.cache.find(v => v.token === token) || null);
                    }
                    remove(token: string): Promise<void> {
                        return Promise.resolve();
                    }
                }
                const TokenMgr = new TokenManager(new IO(), 'sha256');
                const TokenInfo = await TokenMgr.get(TokenText);
                expect(TokenInfo).toBeNull();
            });
            it('revoke', async () => {
                const ID = uuuidv4();
                const ExpireDate = new Date(Date.now() + 3600 * 1000);
                const TokenText = generate({ length: 32, charset: 'alphanumeric' });
                class IO implements IOManagerBase {
                    cache = [
                        {
                            token: SupportedHashMethods.md5(TokenText),
                            expires_at: ExpireDate,
                            linked_id: ID,
                            scopes: 'user.read,user.write',
                        },
                    ];
                    write(data: TokenGenInformation<string>): Promise<void> {
                        return Promise.resolve();
                    }
                    read(token: string): Promise<TokenInformation<string> | null> {
                        return Promise.resolve(this.cache.find(v => v.token === token) || null);
                    }
                    remove(token: string): Promise<void> {
                        this.cache = this.cache.filter(v => v.token !== token);
                        return Promise.resolve();
                    }
                }
                const TokenMgr = new TokenManager(new IO(), 'md5');
                const BeforeRevoke = await TokenMgr.get(TokenText);
                expect(BeforeRevoke).toStrictEqual({
                    expires_at: ExpireDate,
                    linked_id: ID,
                    scopes: ['user.read', 'user.write'],
                });
                await TokenMgr.revoke(TokenText);
                const TokenInfo = await TokenMgr.get(TokenText);
                expect(TokenInfo).toBeNull();
            });
        });

        describe('CustomMethod', () => {
            const HashedMethod = (text: string) => SupportedHashMethods.md5(SupportedHashMethods.sha256(text));
            it('create', async () => {
                const ID = uuuidv4();
                const ExpireDate = new Date(Date.now() + 3600 * 1000);
                class IO implements IOManagerBase {
                    write(data: TokenGenInformation<string>): Promise<void> {
                        expect(data.token).toMatch(/^[0-9A-Za-z]{32}$/);
                        const Expect = {
                            token: data.token, // mockしてないので、こうしないとテストが通らない
                            linked_id: ID,
                            scopes: 'user.read,user.write',
                            expires_at: ExpireDate,
                        };
                        expect(data).toStrictEqual(Expect);
                        return Promise.resolve();
                    }
                    read(token: string): Promise<TokenInformation<string> | null> {
                        return Promise.resolve(null);
                    }
                    remove(token: string): Promise<void> {
                        return Promise.resolve();
                    }
                }
                const TokenMgr = new TokenManager(new IO(), HashedMethod);
                const TokenText = await TokenMgr.create(ID, ['user.read', 'user.write'], ExpireDate);
                expect(TokenText).toMatch(/^[0-9A-Za-z]{32}$/);
            });
            it('get/ok', async () => {
                const ID = uuuidv4();
                const ExpireDate = new Date(Date.now() + 3600 * 1000);
                const TokenText = generate({ length: 32, charset: 'alphanumeric' });
                class IO implements IOManagerBase {
                    cache = [
                        {
                            token: HashedMethod(TokenText),
                            expires_at: ExpireDate,
                            linked_id: ID,
                            scopes: 'user.read,user.write',
                        },
                    ];
                    write(data: TokenGenInformation<string>): Promise<void> {
                        return Promise.resolve();
                    }
                    read(token: string): Promise<TokenInformation<string> | null> {
                        return Promise.resolve(this.cache.find(v => v.token === token) || null);
                    }
                    remove(token: string): Promise<void> {
                        return Promise.resolve();
                    }
                }
                const TokenMgr = new TokenManager(new IO(), HashedMethod);
                const TokenInfo = await TokenMgr.get(TokenText);
                const Expect = {
                    expires_at: ExpireDate,
                    linked_id: ID,
                    scopes: ['user.read', 'user.write'],
                };
                expect(TokenInfo).toStrictEqual(Expect);
            });
            it('get/expired', async () => {
                const ID = uuuidv4();
                const ExpireDate = new Date(Date.now() - 3600 * 1000);
                const TokenText = generate({ length: 32, charset: 'alphanumeric' });
                class IO implements IOManagerBase {
                    cache = [
                        {
                            token: HashedMethod(TokenText),
                            expires_at: ExpireDate,
                            linked_id: ID,
                            scopes: 'user.read,user.write',
                        },
                    ];
                    write(data: TokenGenInformation<string>): Promise<void> {
                        return Promise.resolve();
                    }
                    read(token: string): Promise<TokenInformation<string> | null> {
                        return Promise.resolve(this.cache.find(v => v.token === token) || null);
                    }
                    remove(token: string): Promise<void> {
                        return Promise.resolve();
                    }
                }
                const TokenMgr = new TokenManager(new IO(), HashedMethod);
                const TokenInfo = await TokenMgr.get(TokenText);
                expect(TokenInfo).toBeNull();
            });
            it('revoke', async () => {
                const ID = uuuidv4();
                const ExpireDate = new Date(Date.now() + 3600 * 1000);
                const TokenText = generate({ length: 32, charset: 'alphanumeric' });
                class IO implements IOManagerBase {
                    cache = [
                        {
                            token: HashedMethod(TokenText),
                            expires_at: ExpireDate,
                            linked_id: ID,
                            scopes: 'user.read,user.write',
                        },
                    ];
                    write(data: TokenGenInformation<string>): Promise<void> {
                        return Promise.resolve();
                    }
                    read(token: string): Promise<TokenInformation<string> | null> {
                        return Promise.resolve(this.cache.find(v => v.token === token) || null);
                    }
                    remove(token: string): Promise<void> {
                        this.cache = this.cache.filter(v => v.token !== token);
                        return Promise.resolve();
                    }
                }
                const TokenMgr = new TokenManager(new IO(), HashedMethod);
                const BeforeRevoke = await TokenMgr.get(TokenText);
                expect(BeforeRevoke).toStrictEqual({
                    expires_at: ExpireDate,
                    linked_id: ID,
                    scopes: ['user.read', 'user.write'],
                });
                await TokenMgr.revoke(TokenText);
                const TokenInfo = await TokenMgr.get(TokenText);
                expect(TokenInfo).toBeNull();
            });
        });
    });
    describe('Use Salt', () => {
        const Params = {
            length: 32,
            salt: 'test_salt',
        };
        it('init/no hashed method', () => {
            class IO implements IOManagerBase {
                write(data: TokenGenInformation<string>): Promise<void> {
                    return Promise.resolve();
                }
                read(token: string): Promise<TokenInformation<string> | null> {
                    return Promise.resolve(null);
                }
                remove(token: string): Promise<void> {
                    return Promise.resolve();
                }
            }
            expect(() => new TokenManager(new IO(), 'not_supported', Params)).toThrow('Hash method not supported');
        });
        it('CreateTokenText', async () => {
            class IO {
                private callCount = 0;
                write(data: TokenGenInformation<string>): Promise<void> {
                    return Promise.resolve();
                }
                read(token: string): Promise<TokenInformation<string> | null> {
                    const Ret =
                        this.callCount++ === 0
                            ? {
                                  expires_at: new Date(Date.now() + 3600 * 1000),
                                  linked_id: 'test',
                                  scopes: 'user.read,user.write',
                              }
                            : null;
                    return Promise.resolve(Ret);
                }
                remove(token: string): Promise<void> {
                    return Promise.resolve();
                }
            }
            const TokenMgr = new TokenManager(new IO(), 'plain', Params);
            const TokenText = await TokenMgr['CreateTokenText']();
            expect(TokenText).toMatch(/^[0-9A-Za-z]{32}$/);
        });
        describe('SupportedMethod', () => {
            it('create', async () => {
                const ID = uuuidv4();
                const ExpireDate = new Date(Date.now() + 3600 * 1000);
                class IO implements IOManagerBase {
                    write(data: TokenGenInformation<string>): Promise<void> {
                        expect(data.token).toMatch(/^test_salt[0-9A-Za-z]{32}$/);
                        const Expect = {
                            token: data.token, // mockしてないので、こうしないとテストが通らない
                            linked_id: ID,
                            scopes: 'user.read,user.write',
                            expires_at: ExpireDate,
                        };
                        expect(data).toStrictEqual(Expect);
                        return Promise.resolve();
                    }
                    read(token: string): Promise<TokenInformation<string> | null> {
                        return Promise.resolve(null);
                    }
                    remove(token: string): Promise<void> {
                        return Promise.resolve();
                    }
                }
                const TokenMgr = new TokenManager(new IO(), 'plain', Params);
                const TokenText = await TokenMgr.create(ID, ['user.read', 'user.write'], ExpireDate);
                expect(TokenText).toMatch(/^[0-9A-Za-z]{32}$/);
            });
            it('get/ok', async () => {
                const ID = uuuidv4();
                const ExpireDate = new Date(Date.now() + 3600 * 1000);
                const TokenText = generate({ length: 32, charset: 'alphanumeric' });
                class IO implements IOManagerBase {
                    cache = [
                        {
                            token: SupportedHashMethods.sha256(Params.salt + TokenText),
                            expires_at: ExpireDate,
                            linked_id: ID,
                            scopes: 'user.read,user.write',
                        },
                    ];
                    write(data: TokenGenInformation<string>): Promise<void> {
                        return Promise.resolve();
                    }
                    read(token: string): Promise<TokenInformation<string> | null> {
                        return Promise.resolve(this.cache.find(v => v.token === token) || null);
                    }
                    remove(token: string): Promise<void> {
                        return Promise.resolve();
                    }
                }
                const TokenMgr = new TokenManager(new IO(), 'sha256', Params);
                const TokenInfo = await TokenMgr.get(TokenText);
                const Expect = {
                    expires_at: ExpireDate,
                    linked_id: ID,
                    scopes: ['user.read', 'user.write'],
                };
                expect(TokenInfo).toStrictEqual(Expect);
            });
            it('get/expired', async () => {
                const ID = uuuidv4();
                const ExpireDate = new Date(Date.now() - 3600 * 1000);
                const TokenText = generate({ length: 32, charset: 'alphanumeric' });
                class IO implements IOManagerBase {
                    cache = [
                        {
                            token: SupportedHashMethods.sha256(Params.salt + TokenText),
                            expires_at: ExpireDate,
                            linked_id: ID,
                            scopes: 'user.read,user.write',
                        },
                    ];
                    write(data: TokenGenInformation<string>): Promise<void> {
                        return Promise.resolve();
                    }
                    read(token: string): Promise<TokenInformation<string> | null> {
                        return Promise.resolve(this.cache.find(v => v.token === token) || null);
                    }
                    remove(token: string): Promise<void> {
                        return Promise.resolve();
                    }
                }
                const TokenMgr = new TokenManager(new IO(), 'sha256', Params);
                const TokenInfo = await TokenMgr.get(TokenText);
                expect(TokenInfo).toBeNull();
            });
            it('revoke', async () => {
                const ID = uuuidv4();
                const ExpireDate = new Date(Date.now() + 3600 * 1000);
                const TokenText = generate({ length: 32, charset: 'alphanumeric' });
                class IO implements IOManagerBase {
                    cache = [
                        {
                            token: SupportedHashMethods.md5(Params.salt + TokenText),
                            expires_at: ExpireDate,
                            linked_id: ID,
                            scopes: 'user.read,user.write',
                        },
                    ];
                    write(data: TokenGenInformation<string>): Promise<void> {
                        return Promise.resolve();
                    }
                    read(token: string): Promise<TokenInformation<string> | null> {
                        return Promise.resolve(this.cache.find(v => v.token === token) || null);
                    }
                    remove(token: string): Promise<void> {
                        this.cache = this.cache.filter(v => v.token !== token);
                        return Promise.resolve();
                    }
                }
                const TokenMgr = new TokenManager(new IO(), 'md5', Params);
                const BeforeRevoke = await TokenMgr.get(TokenText);
                expect(BeforeRevoke).toStrictEqual({
                    expires_at: ExpireDate,
                    linked_id: ID,
                    scopes: ['user.read', 'user.write'],
                });
                await TokenMgr.revoke(TokenText);
                const TokenInfo = await TokenMgr.get(TokenText);
                expect(TokenInfo).toBeNull();
            });
        });
        describe('CustomMethod', () => {
            const HashedMethod = (text: string) => SupportedHashMethods.md5(SupportedHashMethods.sha256(text));
            it('create', async () => {
                const ID = uuuidv4();
                const ExpireDate = new Date(Date.now() + 3600 * 1000);
                class IO implements IOManagerBase {
                    write(data: TokenGenInformation<string>): Promise<void> {
                        expect(data.token).toMatch(/^[0-9A-Za-z]{32}$/);
                        const Expect = {
                            token: data.token, // mockしてないので、こうしないとテストが通らない
                            linked_id: ID,
                            scopes: 'user.read,user.write',
                            expires_at: ExpireDate,
                        };
                        expect(data).toStrictEqual(Expect);
                        return Promise.resolve();
                    }
                    read(token: string): Promise<TokenInformation<string> | null> {
                        return Promise.resolve(null);
                    }
                    remove(token: string): Promise<void> {
                        return Promise.resolve();
                    }
                }
                const TokenMgr = new TokenManager(new IO(), HashedMethod, Params);
                const TokenInfo = await TokenMgr.create(ID, ['user.read', 'user.write'], ExpireDate);
                expect(TokenInfo).toMatch(/^[0-9A-Za-z]{32}$/);
            });
            it('get/ok', async () => {
                const ID = uuuidv4();
                const ExpireDate = new Date(Date.now() + 3600 * 1000);
                const TokenText = generate({ length: 32, charset: 'alphanumeric' });
                class IO implements IOManagerBase {
                    cache = [
                        {
                            token: HashedMethod(Params.salt + TokenText),
                            expires_at: ExpireDate,
                            linked_id: ID,
                            scopes: 'user.read,user.write',
                        },
                    ];
                    write(data: TokenGenInformation<string>): Promise<void> {
                        return Promise.resolve();
                    }
                    read(token: string): Promise<TokenInformation<string> | null> {
                        return Promise.resolve(this.cache.find(v => v.token === token) || null);
                    }
                    remove(token: string): Promise<void> {
                        return Promise.resolve();
                    }
                }
                const TokenMgr = new TokenManager(new IO(), HashedMethod, Params);
                const TokenInfo = await TokenMgr.get(TokenText);
                const Expect = {
                    expires_at: ExpireDate,
                    linked_id: ID,
                    scopes: ['user.read', 'user.write'],
                };
                expect(TokenInfo).toStrictEqual(Expect);
            });
            it('get/expired', async () => {
                const ID = uuuidv4();
                const ExpireDate = new Date(Date.now() - 3600 * 1000);
                const TokenText = generate({ length: 32, charset: 'alphanumeric' });
                class IO implements IOManagerBase {
                    cache = [
                        {
                            token: HashedMethod(Params.salt + TokenText),
                            expires_at: ExpireDate,
                            linked_id: ID,
                            scopes: 'user.read,user.write',
                        },
                    ];
                    write(data: TokenGenInformation<string>): Promise<void> {
                        return Promise.resolve();
                    }
                    read(token: string): Promise<TokenInformation<string> | null> {
                        return Promise.resolve(this.cache.find(v => v.token === token) || null);
                    }
                    remove(token: string): Promise<void> {
                        return Promise.resolve();
                    }
                }
                const TokenMgr = new TokenManager(new IO(), HashedMethod, Params);
                const TokenInfo = await TokenMgr.get(TokenText);
                expect(TokenInfo).toBeNull();
            });
            it('revoke', async () => {
                const ID = uuuidv4();
                const ExpireDate = new Date(Date.now() + 3600 * 1000);
                const TokenText = generate({ length: 32, charset: 'alphanumeric' });
                class IO implements IOManagerBase {
                    cache = [
                        {
                            token: HashedMethod(Params.salt + TokenText),
                            expires_at: ExpireDate,
                            linked_id: ID,
                            scopes: 'user.read,user.write',
                        },
                    ];
                    write(data: TokenGenInformation<string>): Promise<void> {
                        return Promise.resolve();
                    }
                    read(token: string): Promise<TokenInformation<string> | null> {
                        return Promise.resolve(this.cache.find(v => v.token === token) || null);
                    }
                    remove(token: string): Promise<void> {
                        this.cache = this.cache.filter(v => v.token !== token);
                        return Promise.resolve();
                    }
                }
                const TokenMgr = new TokenManager(new IO(), HashedMethod, Params);
                const BeforeRevoke = await TokenMgr.get(TokenText);
                expect(BeforeRevoke).toStrictEqual({
                    expires_at: ExpireDate,
                    linked_id: ID,
                    scopes: ['user.read', 'user.write'],
                });
                await TokenMgr.revoke(TokenText);
                const TokenInfo = await TokenMgr.get(TokenText);
                expect(TokenInfo).toBeNull();
            });
        });
    });
});
