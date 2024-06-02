import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Scanner;

/**
 * This class demonstrates encryption and decryption using the AES algorithm.
 */
public class AESEncryptionDecryption {

    // AES encryption algorithm identifier.
    private static final String ALGORITHM = "AES";

    /**
     * Main method to run the encryption/decryption process.
     * @param args command line arguments (not used)
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Prompt the user to choose between encryption and decryption.
        System.out.println("Do you want to (E)ncrypt or (D)ecrypt?");
        String choice = scanner.nextLine().trim().toUpperCase();

        // Prompt for a key that must be of length 16, 24, or 32 bytes.
        System.out.println("Please enter your key (16, 24, or 32 characters):");
        String key = scanner.nextLine().trim();

        // Processing based on the user's choice.
        if (choice.equals("E")) {
            System.out.println("Enter the password to encrypt:");
            String input = scanner.nextLine().trim();
            try {
                String encrypted = encrypt(input, key);
                System.out.println("Encrypted password: " + encrypted);
            } catch (Exception e) {
                System.err.println("Error during encryption: " + e.getMessage());
            }
        } else if (choice.equals("D")) {
            System.out.println("Enter the encrypted password to decrypt:");
            String input = scanner.nextLine().trim();
            try {
                String decrypted = decrypt(input, key);
                System.out.println("Decrypted password: " + decrypted);
            } catch (Exception e) {
                System.err.println("Error during decryption: " + e.getMessage());
            }
        } else {
            System.out.println("Invalid choice. Please choose (E) or (D).");
        }

        // Closing the scanner to prevent resource leaks.
        scanner.close();
    }

    /**
     * Encrypts plaintext data using AES encryption.
     * @param data The plaintext to encrypt.
     * @param key The encryption key.
     * @return The encrypted data as a Base64 encoded string.
     * @throws Exception if an error occurs during encryption.
     */
    public static String encrypt(String data, String key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * Decrypts encrypted data using AES decryption.
     * @param encryptedData The encrypted data to decrypt.
     * @param key The decryption key.
     * @return The decrypted data as a string.
     * @throws Exception if an error occurs during decryption.
     */
    public static String decrypt(String encryptedData, String key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes);
    }
}
