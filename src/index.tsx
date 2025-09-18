import CryptoVault from './NativeCryptoVault';

export default {
  ping: () => CryptoVault.ping(),
  echo: (message: string) => CryptoVault.echo(message),
  getDeviceInfo: async () => CryptoVault.getDeviceInfo(),
  getRandomId: async () => CryptoVault.getRandomId(),
  hashString: async (message: string) => CryptoVault.hashString(message),
  hmacSHA256: async (message: string, key: string) =>
    CryptoVault.hmacSHA256(message, key),
  aesGcmEncrypt: async (plainText: string, keyAlias: string) =>
    CryptoVault.aesGcmEncrypt(plainText, keyAlias),
  aesGcmDecrypt: async (plainText: string, keyBase64: string) =>
    CryptoVault.aesGcmDecrypt(plainText, keyBase64),
  getRandomBytes: (length: number) => CryptoVault.getRandomBytes(length),
  generateSecureKey: (alias: string) => CryptoVault.generateSecureKey(alias),
  aesGcmEncryptWithHmac: (plainText: string, keyBase64: string) =>
    CryptoVault.aesGcmEncryptWithHmac(plainText, keyBase64),
  aesGcmDecryptWithHmac: (cipherTextBase64: string, keyBase64: string) =>
    CryptoVault.aesGcmDecryptWithHmac(cipherTextBase64, keyBase64),
  generateSecureKeyWithAuth: (alias: string, authValiditySeconds = -1) =>
    CryptoVault.generateSecureKeyWithAuth(alias, authValiditySeconds),
  aesGcmEncryptWithAuth: (
    plainText: string,
    alias: string,
    authValiditySeconds?: number
  ) => CryptoVault.aesGcmEncryptWithAuth(plainText, alias, authValiditySeconds),
  aesGcmDecryptWithAuth: (
    cipherTextBase64: string,
    alias: string,
    authValiditySeconds?: number
  ) =>
    CryptoVault.aesGcmDecryptWithAuth(
      cipherTextBase64,
      alias,
      authValiditySeconds
    ),
  isDeviceSecure: () => CryptoVault.isDeviceSecure(),
  backupKey: (alias: string) => CryptoVault.backupKey(alias),
  restoreKey: (alias: string, backupBlobBase64: string) =>
    CryptoVault.restoreKey(alias, backupBlobBase64),
  initVault: (authValiditySeconds = 300) => {
    CryptoVault.initVault(authValiditySeconds);
  },
  lockVault: async () => {
    return CryptoVault.lockVault();
  },
  unlockVault: async (authData: string) => {
    return CryptoVault.unlockVault(authData);
  },
  isVaultLocked: async () => {
    return CryptoVault.isVaultLocked();
  },
  backupVault: (password: string) => CryptoVault.backupVault(password),
  restoreVault: (password: string, backupBlob: string) =>
    CryptoVault.restoreVault(password, backupBlob),
  setVaultPin: (pin: string) => CryptoVault.setVaultPin(pin),
  unlockVaultWithPin: (pin: string) => CryptoVault.unlockVaultWithPin(pin),
  setVaultPolicy: (
    policy: 'NONE' | 'PIN' | 'BIOMETRIC' | 'TIMEOUT',
    timeoutMs?: number
  ) => CryptoVault.setVaultPolicy(policy, timeoutMs),
  getVaultPolicy: () => CryptoVault.getVaultPolicy(),
  aesGcmEncryptRaw: (plainText: string, keyBase64: string) =>
    CryptoVault.aesGcmEncryptRaw(plainText, keyBase64),
  aesGcmDecryptRaw: (cipherTextBase64: string, keyBase64: string) =>
    CryptoVault.aesGcmDecryptRaw(cipherTextBase64, keyBase64),
};
