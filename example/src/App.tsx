import { useEffect } from 'react';
import { Text, View } from 'react-native';
import CryptoVault from 'react-native-crypto-vault'; // your wrapper

export default function App() {
  useEffect(() => {
    runTests();
    runUtilityTests();
    runVaultPolicyTests();
    backupValultTest();
    testRemainingMethods();
  }, []);

  const runTests = async () => {
    try {
      console.log('--- Testing vault and raw AES/HMAC methods ---');

      // 1️⃣ Initialize vault with NONE policy
      await CryptoVault.initVault(300);
      console.log('✅ Vault initialized with policy NONE');

      // 2️⃣ Check vault locked state
      let locked = await CryptoVault.isVaultLocked();
      console.log('Vault locked?', locked);

      // 3️⃣ Generate secure key
      const alias = `testKeyAlias_${Date.now()}`;
      const keyResult = await CryptoVault.generateSecureKey(alias);
      console.log('✅ Key generated successfully for alias:', keyResult);

      // 4️⃣ AES-GCM encrypt/decrypt raw
      const plainText = 'Hello CryptoVault!';
      const keyBase64 = await CryptoVault.backupKey(alias); // get base64 exportable key

      const encryptedRaw = await CryptoVault.aesGcmEncryptRaw(
        plainText,
        keyBase64
      );
      console.log('✅ Raw AES-GCM encrypted:', encryptedRaw);

      const decryptedRaw = await CryptoVault.aesGcmDecryptRaw(
        encryptedRaw,
        keyBase64
      );
      console.log('✅ Raw AES-GCM decrypted:', decryptedRaw);

      if (decryptedRaw === plainText) {
        console.log('🎯 Raw AES-GCM encryption/decryption success!');
      } else {
        console.error('❌ Raw AES-GCM mismatch!');
      }

      // 5️⃣ AES-GCM + HMAC encrypt/decrypt
      const encryptedHmac = await CryptoVault.aesGcmEncryptWithHmac(
        plainText,
        keyBase64
      );
      console.log('✅ AES-GCM + HMAC encrypted:', encryptedHmac);

      const decryptedHmac = await CryptoVault.aesGcmDecryptWithHmac(
        encryptedHmac,
        keyBase64
      );
      console.log('✅ AES-GCM + HMAC decrypted:', decryptedHmac);

      if (decryptedHmac === plainText) {
        console.log('🎯 AES-GCM + HMAC encryption/decryption success!');
      } else {
        console.error('❌ AES-GCM + HMAC mismatch!');
      }

      // 6️⃣ Backup and restore key
      const backupBlob = await CryptoVault.backupKey(alias);
      console.log('✅ Backup key Base64:', backupBlob);

      const restoredAlias = alias + '_restored';
      await CryptoVault.restoreKey(restoredAlias, backupBlob);
      console.log('✅ Key restored with alias:', restoredAlias);

      // 7️⃣ Vault lock/unlock (policy NONE, so vault always unlocked)
      await CryptoVault.lockVault();
      locked = await CryptoVault.isVaultLocked();
      console.log('Vault locked after lockVault():', locked);

      await CryptoVault.unlockVault(''); // unlockVault with policy NONE
      locked = await CryptoVault.isVaultLocked();
      console.log('Vault locked after unlockVault():', locked);

      console.log('--- All non-auth methods test finished ---');
    } catch (e) {
      console.error('Test failed:', e);
    }
  };

  const runUtilityTests = async () => {
    try {
      console.log('--- Testing Utility Methods ---');

      // 1️⃣ Ping / Echo
      const pingResult = CryptoVault.ping();
      console.log('✅ Ping:', pingResult);

      const echoResult = CryptoVault.echo('Hello Echo');
      console.log('✅ Echo:', echoResult);

      // 2️⃣ Device Info
      const deviceInfo = await CryptoVault.getDeviceInfo();
      console.log('✅ Device Info:', deviceInfo);

      // 3️⃣ Random ID
      const randomId = await CryptoVault.getRandomId();
      console.log('✅ Random ID:', randomId);

      // 4️⃣ Hash String
      const hash = await CryptoVault.hashString('HelloHash');
      console.log('✅ Hash of "HelloHash":', hash);

      // 5️⃣ HMAC-SHA256
      const hmac = await CryptoVault.hmacSHA256('HelloHmac', 'SecretKey123');
      console.log('✅ HMAC-SHA256 of "HelloHmac":', hmac);

      // 6️⃣ Random Bytes
      const randomBytes = await CryptoVault.getRandomBytes(16);
      console.log('✅ Random Bytes (16):', randomBytes);

      console.log('--- Utility Methods test finished ---');
    } catch (e) {
      console.error('❌ Utility test failed:', e);
    }
  };

  const runVaultPolicyTests = async () => {
    try {
      console.log('--- Testing Vault Policy / PIN / Device Security ---');

      // 1️⃣ Device Secure Check
      const deviceSecure = await CryptoVault.isDeviceSecure();
      console.log('✅ Device Secure:', deviceSecure);

      // 2️⃣ Set PIN first if not set
      const pinSet = true; // you may implement a method like isPinSet()
      if (!pinSet) {
        await CryptoVault.setVaultPin('1234');
        console.log('✅ PIN set successfully');
      }

      // 3️⃣ Set Vault Policy
      await CryptoVault.setVaultPolicy('PIN');
      console.log('✅ Vault policy set');

      // 4️⃣ Check vault lock
      const isVaultLocked = await CryptoVault.isVaultLocked();
      console.log('isVaultLocked', isVaultLocked);

      // 5️⃣ Unlock if locked
      if (isVaultLocked) {
        await CryptoVault.unlockVault('12345');
        console.log('✅ Vault unlocked with PIN');
      }

      console.log('--- Vault Policy / PIN / Device Security test finished ---');
    } catch (e) {
      console.error('❌ Vault Policy test failed:', e);
    }
  };

  const backupValultTest = async () => {
    try {
      console.log('--- Testing Vault Backup & Restore ---');

      const password = 'testPassword123';

      // Backup vault with password
      const backupBlob = await CryptoVault.backupVault(password);
      console.log('✅ Vault backed up. Blob length:', backupBlob.length);

      // (Simulate clearing vault by locking, in real case would also reset/clear keys)
      await CryptoVault.lockVault();
      let locked = await CryptoVault.isVaultLocked();
      console.log('Vault locked after backup:', locked);

      // Restore vault with password
      await CryptoVault.restoreVault(password, backupBlob);
      console.log('✅ Vault restored successfully');

      // Unlock after restore
      await CryptoVault.unlockVault('');
      locked = await CryptoVault.isVaultLocked();
      console.log('Vault locked after restore/unlock:', locked);

      console.log('--- Vault Backup & Restore test finished ---');
    } catch (e) {
      console.error('❌ Vault Backup & Restore test failed:', e);
    }
  };

  const testRemainingMethods = async () => {
    try {
      console.log('--- Testing AES-GCM Encryption / Decryption ---');

      // AES-GCM (non-auth) test
      const keyAlias = `aesKey_${Date.now()}`;
      const genKey = await CryptoVault.generateSecureKey(keyAlias);
      console.log('✅ Secure key generated:', genKey);

      const plainText = 'HelloAES';
      const encrypted = await CryptoVault.aesGcmEncrypt(plainText, keyAlias);
      console.log('✅ Encrypted text:', encrypted);

      const decrypted = await CryptoVault.aesGcmDecrypt(encrypted, keyAlias);
      console.log('✅ Decrypted text:', decrypted);

      if (decrypted === plainText) {
        console.log('🎉 AES-GCM round trip successful!');
      } else {
        console.log('❌ AES-GCM round trip failed!');
      }

      console.log('--- AES-GCM Encryption / Decryption test finished ---');

      // AES-GCM with Auth test
      console.log('--- Testing AES-GCM with Auth ---');
      const authKeyAlias = `authKey_${Date.now()}`;

      await CryptoVault.generateSecureKeyWithAuth(authKeyAlias);
      console.log('✅ Secure key with auth generated');

      const authPlainText = 'HelloAuthAES';
      const encryptedAuth = await CryptoVault.aesGcmEncryptWithAuth(
        authPlainText,
        authKeyAlias
      );
      console.log('✅ Encrypted with Auth:', encryptedAuth);

      const decryptedAuth = await CryptoVault.aesGcmDecryptWithAuth(
        encryptedAuth,
        authKeyAlias
      );
      console.log('✅ Decrypted with Auth:', decryptedAuth);

      if (decryptedAuth === authPlainText) {
        console.log('🎉 AES-GCM with Auth round trip successful!');
      } else {
        console.log('❌ AES-GCM with Auth round trip failed!');
      }

      console.log('--- AES-GCM with Auth test finished ---');
    } catch (e) {
      console.error('Test failed:', e);
    }
  };

  return (
    <View>
      <Text>Testing Authenticated AES Encrypt & Decrypt</Text>
    </View>
  );
}
