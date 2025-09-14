import { useEffect, useState } from 'react';
import { Text, StyleSheet, ScrollView, View, Button } from 'react-native';
import CryptoVault from 'react-native-crypto-vault';
export default function App() {
  const [deviceInfo, setDeviceInfo] = useState<string>();
  const [randomUUDID, setRandomUUDID] = useState<string>();
  const [hashString, setHashString] = useState<string>();
  const [hmacSHA256, setHmacSHA256] = useState<string>();
  const [aesGcmEncrypt, setAesGcmEncrypt] = useState<string>();
  const [aesGcmDecrypt, setAesGcmDecrypt] = useState<string>();
  const [getSecureKey, setSecureKey] = useState<string>();
  const [hmacDecrypt, sethmscDecrypt] = useState<string>();
  const [hmacEncrypt, sethmscEnrypt] = useState<string>();
  const [getAuthSecureKey, setAuthSecureKey] = useState<string>();
  const [aesAuthGcmEncrypt, setAuthAesGcmEncrypt] = useState<string>();
  const [aesAuthGcmDecrypt, setAuthAesGcmDecrypt] = useState<string>();
  const [aesGcmEncryptWithAuth, setAesGcmEncryptWithAuth] = useState<string>();
  const [aesGcmDecryptWithAuth, setAesGcmDecryptWithAuth] = useState<string>();
  const [isDeviceSecure, setIsDeviceSecure] = useState<boolean>();
  const [locked, setLocked] = useState(true);
  //const [backupBlob, setBackupBlob] = useState<string>();
  let backupBlob: string | null = null;
  useEffect(() => {
    getdeviceIndo();
    getRandomUUDID();
    getHashString();
    getHmacString();
    generateaesGcm();
    generateSecureKey();
    generateSecureKeyWithAuth();
    generateaesEncryptHmac();
    generateaesGcmWithAuth();
    generateSecureKeyWithAuth();
    testAuthEncryption();
    checkIsDeviceSecure();
    CryptoVault.initVault(1); // 1 minute session
    updateLockState();
  }, []);

  const updateLockState = async () => {
    const isLocked = await CryptoVault.isVaultLocked();
    setLocked(isLocked);
  };
  const checkIsDeviceSecure = async () => {
    try {
      const secure = await CryptoVault.isDeviceSecure();
      console.log('checkIsDeviceSecure result:', secure); // ✅ log actual value
      setIsDeviceSecure(secure);
    } catch (e) {
      console.error('isDeviceSecure failed:', e);
    }
  };

  const generateSecureKeyWithAuth = async () => {
    const alias = 'my_app_biometric_key';

    try {
      const secureKey = await CryptoVault.generateSecureKeyWithAuth(alias, 30); // -1 → prompt every time
      setAuthSecureKey(secureKey);
    } catch (error: any) {
      console.error('Key generation failed:', error.message);
    }
  };
  const getdeviceIndo = async () => {
    const deviceid: string = await CryptoVault.getDeviceInfo();
    setDeviceInfo(deviceid);
  };
  const getRandomUUDID = async () => {
    const randomUUDID: string = await CryptoVault.getRandomId();
    setRandomUUDID(randomUUDID);
  };
  const getHashString = async () => {
    const hashString: string = await CryptoVault.hashString('Cryptovalut');
    setHashString(hashString);
  };

  const getHmacString = async () => {
    const keyBase64 = await CryptoVault.getRandomBytes(32);
    const hmscString = await CryptoVault.hmacSHA256('Cryptovalut', keyBase64);
    setHmacSHA256(hmscString);
  };

  const generateaesGcm = async () => {
    const alias = 'my_app_aes_key';

    // Generate Keystore key once
    await CryptoVault.generateSecureKey(alias);

    const plain = 'Hello secret';

    // Encrypt
    const cipherBase64 = await CryptoVault.aesGcmEncrypt(plain, alias);
    setAesGcmEncrypt(cipherBase64);
    console.log('cipherBase64', cipherBase64);

    // Decrypt
    const decrypted = await CryptoVault.aesGcmDecrypt(cipherBase64, alias);
    setAesGcmDecrypt(decrypted);
    console.log('decrypted', decrypted);
  };

  const generateaesGcmWithAuth = async () => {
    const alias = 'my_app_biometric_key';
    const plain = 'Hello secret';

    try {
      // Encrypt (will prompt biometric/PIN if required)
      const cipherBase64 = await CryptoVault.aesGcmEncrypt(plain, alias);
      setAuthAesGcmEncrypt(cipherBase64);
      console.log('Encrypted:', cipherBase64);

      // Decrypt (will prompt biometric/PIN again if -1)
      const decrypted = await CryptoVault.aesGcmDecrypt(cipherBase64, alias);
      setAuthAesGcmDecrypt(decrypted);
      console.log('Decrypted:', decrypted);
    } catch (error: any) {
      // Handle user cancel / authentication failure
      if (error.code === 'USER_NOT_AUTHENTICATED') {
        console.log('User canceled authentication or failed.');
      } else if (error.code === 'KEY_INVALIDATED') {
        console.log('Key invalidated (biometric changed). Generate a new key.');
      } else {
        console.error('Encryption/Decryption failed:', error.message);
      }
    }
  };
  const generateSecureKey = async () => {
    const alias = 'my_app_aes_key';
    const secureKey = await CryptoVault.generateSecureKey(alias);
    setSecureKey(secureKey);
  };

  const generateaesEncryptHmac = async () => {
    const key = await CryptoVault.getRandomBytes(32);
    const message = 'Hello authenticated encryption';

    const encrypted = await CryptoVault.aesGcmEncryptWithHmac(message, key);
    sethmscEnrypt(encrypted);

    const decrypted = await CryptoVault.aesGcmDecryptWithHmac(encrypted, key);
    sethmscDecrypt(decrypted);
  };

  async function doBackup() {
    console.log('doBackup');
    try {
      backupBlob = await CryptoVault.backupVault('myStrongPassword123!');
      console.log('Backup successful:', backupBlob);
    } catch (e) {
      console.error('Backup failed:', e);
    }
  }

  async function doRestore() {
    try {
      if (!backupBlob) throw new Error('No backup available');
      await CryptoVault.restoreVault('myStrongPassword123!', backupBlob);
      console.log('Restore successful!');
    } catch (e) {
      console.error('Restore failed:', e);
    }
  }

  const testAuthEncryption = async () => {
    const alias = 'my_app_biometric_key';
    try {
      const cipher = await CryptoVault.aesGcmEncryptWithAuth(
        'Super secret message',
        alias
      );
      setAesGcmEncryptWithAuth(cipher);

      const plain = await CryptoVault.aesGcmDecryptWithAuth(cipher, alias);
      setAesGcmDecryptWithAuth(plain);
    } catch (e: any) {
      console.log('testAuthEncryption', e);
      if (e.code === 'VAULT_LOCKED') {
        // Prompt user to unlock vault
        await CryptoVault.unlockVault('');
        // Retry the operation
      }
      console.error('Auth encryption/decryption failed:', e);
    }
  };

  const unlockPinVault = async () => {
    try {
      await CryptoVault.unlockVaultWithPin('123');
    } catch (error) {
      console.log('unlockVault', error);
    }
  };
  const setPinVault = async () => {
    console.log('setPinVault called');
    try {
      await CryptoVault.setVaultPin('123');
    } catch (error) {
      console.log('unlockVault', error);
    }
  };
  return (
    <ScrollView style={styles.container}>
      <View
        style={{ justifyContent: 'center', alignItems: 'center', margin: '1%' }}
      >
        <Text style={styles.text}>ping: {CryptoVault.ping()}</Text>
        <Text style={styles.text}>message: {CryptoVault.echo('Crypto')}</Text>
        <Text style={styles.text}>device info: {deviceInfo}</Text>
        <Text style={styles.text}>randomUUDID info: {randomUUDID}</Text>
        <Text style={styles.text}>hashstring info: {hashString}</Text>
        <Text style={styles.text}>hmscs256tring info: {hmacSHA256}</Text>
        <Text style={styles.text}>AesGcmEncrypt info: {aesGcmEncrypt}</Text>
        <Text style={styles.text}>AesGcmDecrypt info: {aesGcmDecrypt}</Text>
        <Text style={styles.text}>SecureKey info: {getSecureKey}</Text>
        <Text style={styles.text}>hmscDecrypt info: {hmacEncrypt}</Text>
        <Text style={styles.text}>hmscEncrypt info: {hmacDecrypt}</Text>
        <Text style={styles.text}>AuthSecureKey info: {getAuthSecureKey}</Text>
        <Text style={styles.text}>
          AuthAesGcmEncrypt info: {aesAuthGcmEncrypt}
        </Text>
        <Text style={styles.text}>
          AuthAesGcmDecrypt info: {aesAuthGcmDecrypt}
        </Text>
        <Text style={styles.text}>
          AuthAesGcmEncryptWithAuth info: {aesGcmEncryptWithAuth}
        </Text>
        <Text style={styles.text}>
          AuthAesGcmDecryptWithAuth info: {aesGcmDecryptWithAuth}
        </Text>
        <Text style={styles.text}>
          isDeviceSecure info: {isDeviceSecure?.toString()}
        </Text>
        <Text>Vault is {locked ? 'Locked' : 'Unlocked'}</Text>
        <Button
          title="Lock Vault"
          onPress={async () => {
            await CryptoVault.lockVault();
            updateLockState();
          }}
        />
        <Button
          title="Unlock Vault"
          onPress={async () => {
            await CryptoVault.unlockVault('dummyPIN');
            updateLockState();
          }}
        />
        <Button title="Backup Vault" onPress={doBackup} />
        <Button title="Restore Vault" onPress={doRestore} />
        <Button title="set Vault pin" onPress={() => setPinVault()} />
        <Button title="unlock Vault pin" onPress={() => unlockPinVault()} />
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  text: {
    padding: '1%',
    margin: '1%',
  },
});
