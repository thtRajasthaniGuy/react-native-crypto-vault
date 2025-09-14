it.todo('write a test');
import Vault from '../NativeCryptoVault';
jest.mock('../NativeCryptoVault');

describe('CryptoVault JS API', () => {
  it('should return pong when ping() is called', () => {
    expect(Vault.ping()).toBe('pong');
  });
});

jest.mock('../NativeCryptoVault');

describe('CryptoVault Echo api', () => {
  it('should return the same string which is passed in echo', () => {
    expect(Vault.echo('hello')).toBe('hello');
    expect(Vault.echo('crypto')).toBe('crypto');
  });
});

test('getRandomId should return a UUID', async () => {
  const id = await Vault.getRandomId();
  expect(typeof id).toBe('string');
  expect(id.length).toBeGreaterThan(0);
});
