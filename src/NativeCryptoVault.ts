import { TurboModuleRegistry, type TurboModule } from 'react-native';

export interface Spec extends TurboModule {
  ping(): string;
  echo(message: string): string;
  getDeviceInfo(): Promise<string>;
  getRandomId(): Promise<string>;
  hashString(message: string): Promise<string>;
  hmacSHA256(message: string, key: string): Promise<string>;
  aesGcmEncrypt(plainText: string, keyAlias: string): Promise<string>;
  aesGcmDecrypt(cipherText: string, keyAlias: string): Promise<string>;
  getRandomBytes(length: number): Promise<string>;
  generateSecureKey(alias: string): Promise<string>;
  aesGcmEncryptWithHmac(plainText: string, keyBase64: string): Promise<string>;
  aesGcmDecryptWithHmac(
    cipherTextBase64: string,
    keyBase64: string
  ): Promise<string>;
  generateSecureKeyWithAuth(
    alias: string,
    authValiditySeconds?: number
  ): Promise<string>;
  aesGcmEncryptWithAuth(plainText: string, alias: string): Promise<string>;
  aesGcmDecryptWithAuth(
    cipherTextBase64: string,
    alias: string
  ): Promise<string>;
  isDeviceSecure(): Promise<boolean>;
  backupKey(alias: string): Promise<string>;
  restoreKey(alias: string, backupBlobBase64: string): Promise<string>;
  initVault(authValiditySeconds?: number): void;
  lockVault(): Promise<void>;
  unlockVault(authData: string): Promise<void>;
  isVaultLocked(): Promise<boolean>;
  backupVault(password: string): Promise<string>;
  restoreVault(password: string, backupBlob: string): Promise<boolean>;
  setVaultPin(pin: string): Promise<void>;
  unlockVaultWithPin(pin: string): Promise<void>;
  setVaultPolicy(
    policy: 'NONE' | 'PIN' | 'BIOMETRIC' | 'TIMEOUT'
  ): Promise<void>;
  getVaultPolicy(): Promise<'NONE' | 'PIN' | 'BIOMETRIC' | 'TIMEOUT'>;
}

export default TurboModuleRegistry.getEnforcing<Spec>('CryptoVault');
