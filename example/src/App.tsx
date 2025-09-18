import { useEffect } from 'react';
import { Text, View } from 'react-native';
import CryptoVault from 'react-native-crypto-vault'; // your wrapper

export default function App() {
  useEffect(() => {
    const testAuthAesFlow = async () => {
      try {
        // 1️⃣ Set vault policy to BIOMETRIC
        await CryptoVault.setVaultPolicy('BIOMETRIC');
        console.log('✅ Vault policy set to BIOMETRIC');

        // 2️⃣ Unlock vault with biometric authentication
        await CryptoVault.unlockVault(''); // This will trigger biometric prompt
        console.log('🔓 Vault unlocked');

        // 3️⃣ Generate secure key tied to authentication
        const keyAlias = 'authKey';
        await CryptoVault.generateSecureKeyWithAuth(keyAlias, 300);
        console.log('🔑 Auth AES key generated');

        // 4️⃣ Encrypt (may trigger biometric if auth expired)
        const plaintext = 'Hello Auth AES!';
        const ciphertext = await CryptoVault.aesGcmEncryptWithAuth(
          plaintext,
          keyAlias,
          300 // 5 minute validity
        );
        console.log('🔐 Auth AES encrypted:', ciphertext);

        // 5️⃣ Decrypt (should use cached auth if within validity period)
        const decrypted = await CryptoVault.aesGcmDecryptWithAuth(
          ciphertext,
          keyAlias,
          300
        );
        console.log('🔓 Auth AES decrypted:', decrypted);

        // 6️⃣ Verify
        console.log('✅ Auth AES decryption correct?', decrypted === plaintext);
      } catch (err) {
        console.error('❌ Auth AES test error:', err);
      }
    };

    testAuthAesFlow();
  }, []);

  return (
    <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center' }}>
      <Text>Testing Authenticated AES Encrypt & Decrypt</Text>
    </View>
  );
}
