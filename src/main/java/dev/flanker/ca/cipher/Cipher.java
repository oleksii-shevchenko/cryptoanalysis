package dev.flanker.ca.cipher;

public interface Cipher {
    void encrypt(byte[] data, byte[] key, byte[] ciphertextBuffer);

    default byte[] encrypt(byte[] data, byte[] key) {
        byte[] ciphertext = new byte[data.length];
        encrypt(data, key, ciphertext);
        return ciphertext;
    }

    void decrypt(byte[] data, byte[] key, byte[] messageBuffer);

    default byte[] decrypt(byte[] data, byte[] key) {
        byte[] message = new byte[data.length];
        encrypt(data, key, message);
        return message;
    }
}
