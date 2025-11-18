import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.Scanner;

/**
 * A single Java class containing implementations for 11 common cryptography problems.
 * This class includes static methods for each algorithm and a main method to demonstrate their solutions.
 *
 * Solutions for:
 * 1. Shift Cipher (Encrypt, Decrypt, Brute Force)
 * 2. Multiplicative Cipher (Encrypt, Decrypt, Brute Force)
 * 3. Affine Cipher (Encrypt, Decrypt, Brute Force)
 * 4. Autokey Cipher (Encrypt, Decrypt) - for Rustom/Kelvin problem
 * 5. Playfair Cipher (Encrypt, Decrypt)
 * 6. Hill Cipher (Encrypt, Decrypt, Show Key Inverse)
 * 7. ElGamal Cryptosystem (Key Gen, Encrypt, Decrypt)
 * 8. Rabin-Miller Primality Test
 * 9. Diffie-Hellman Key Exchange
 * 10. RSA Cryptosystem (Key Gen, Encrypt, Decrypt)
 * 11. RSA Digital Signature (Sign, Verify)
 */
public class CryptoLab {

    // Helper to clean plaintext: lowercase and remove non-alphabetic chars
    private static String cleanText(String s, boolean allowSpaces) {
        s = s.toLowerCase();
        String regex = allowSpaces ? "[^a-z ]" : "[^a-z]";
        return s.replaceAll(regex, "");
    }

    // ========================================================================
    // 1. SHIFT CIPHER
    // ========================================================================

    /**
     * Encrypts plaintext using a Shift Cipher.
     * Plaintext is lower, Ciphertext is upper.
     * C = (P + k) % 26
     */
    public static String shiftEncrypt(String text, int key) {
        text = cleanText(text, false);
        StringBuilder sb = new StringBuilder();
        for (char c : text.toCharArray()) {
            int p = c - 'a';
            int ci = (p + key) % 26;
            sb.append((char) (ci + 'A'));
        }
        return sb.toString();
    }

    /**
     * Decrypts ciphertext using a Shift Cipher.
     * P = (C - k) % 26
     */
    public static String shiftDecrypt(String cipher, int key) {
        cipher = cipher.toUpperCase();
        StringBuilder sb = new StringBuilder();
        for (char c : cipher.toCharArray()) {
            int ci = c - 'A';
            int p = (ci - key) % 26;
            if (p < 0) { // Handle negative modulo
                p += 26;
            }
            sb.append((char) (p + 'a'));
        }
        return sb.toString();
    }

    /**
     * Brute-forces a Shift Cipher, returning all 26 possible decryptions.
     */
    public static void shiftBruteForce(String cipher) {
        System.out.println("--- Shift Cipher Brute Force ---");
        for (int k = 0; k < 26; k++) {
            System.out.printf("Key %2d: %s\n", k, shiftDecrypt(cipher, k));
        }
        System.out.println("---------------------------------");
    }

    // ========================================================================
    // 2. MULTIPLICATIVE CIPHER
    // ========================================================================

    // Helper: Greatest Common Divisor
    private static int gcd(int a, int b) {
        return BigInteger.valueOf(a).gcd(BigInteger.valueOf(b)).intValue();
    }

    // Helper: Modular Multiplicative Inverse
    // Finds 'x' such that (a * x) % m = 1
    private static int modInverse(int a, int m) {
        try {
            return BigInteger.valueOf(a).modInverse(BigInteger.valueOf(m)).intValue();
        } catch (ArithmeticException e) {
            return -1; // No inverse exists
        }
    }

    /**
     * Encrypts plaintext using a Multiplicative Cipher.
     * C = (P * k) % 26
     */
    public static String multiplicativeEncrypt(String text, int key) {
        if (gcd(key, 26) != 1) {
            return "ERROR: Key " + key + " is not coprime with 26. Valid keys are {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25}";
        }
        text = cleanText(text, false);
        StringBuilder sb = new StringBuilder();
        for (char c : text.toCharArray()) {
            int p = c - 'a';
            int ci = (p * key) % 26;
            sb.append((char) (ci + 'A'));
        }
        return sb.toString();
    }

    /**
     * Decrypts ciphertext using a Multiplicative Cipher.
     * P = (C * k_inv) % 26
     */
    public static String multiplicativeDecrypt(String cipher, int key) {
        int inv = modInverse(key, 26);
        if (inv == -1) {
            return "ERROR: Invalid key " + key + ". Cannot find modular inverse.";
        }
        cipher = cipher.toUpperCase();
        StringBuilder sb = new StringBuilder();
        for (char c : cipher.toCharArray()) {
            int ci = c - 'A';
            int p = (ci * inv) % 26;
            sb.append((char) (p + 'a'));
        }
        return sb.toString();
    }

    /**
     * Brute-forces a Multiplicative Cipher, trying all 12 valid keys.
     */
    public static void multiplicativeBruteForce(String cipher) {
        System.out.println("--- Multiplicative Cipher Brute Force ---");
        int[] validKeys = {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25};
        for (int k : validKeys) {
            System.out.printf("Key %2d: %s\n", k, multiplicativeDecrypt(cipher, k));
        }
        System.out.println("-----------------------------------------");
    }

    // ========================================================================
    // 3. AFFINE CIPHER
    // ========================================================================

    /**
     * Encrypts plaintext using an Affine Cipher.
     * C = (P * k1 + k2) % 26
     */
    public static String affineEncrypt(String text, int k1, int k2) {
        if (gcd(k1, 26) != 1) {
            return "ERROR: Key k1=" + k1 + " is not coprime with 26.";
        }
        text = cleanText(text, false);
        StringBuilder sb = new StringBuilder();
        for (char c : text.toCharArray()) {
            int p = c - 'a';
            int ci = (p * k1 + k2) % 26;
            sb.append((char) (ci + 'A'));
        }
        return sb.toString();
    }

    /**
     * Decrypts ciphertext using an Affine Cipher.
     * P = ((C - k2) * k1_inv) % 26
     */
    public static String affineDecrypt(String cipher, int k1, int k2) {
        int inv = modInverse(k1, 26);
        if (inv == -1) {
            return "ERROR: Invalid key k1=" + k1 + ". Cannot find modular inverse.";
        }
        cipher = cipher.toUpperCase();
        StringBuilder sb = new StringBuilder();
        for (char c : cipher.toCharArray()) {
            int ci = c - 'A';
            int p = ((ci - k2) * inv) % 26;
            if (p < 0) {
                p += 26; // Handle negative modulo
            }
            sb.append((char) (p + 'a'));
        }
        return sb.toString();
    }

    /**
     * Brute-forces an Affine Cipher, trying all 312 (12 * 26) possible key pairs.
     */
    public static void affineBruteForce(String cipher) {
        System.out.println("--- Affine Cipher Brute Force ---");
        int[] validK1s = {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25};
        for (int k1 : validK1s) {
            for (int k2 = 0; k2 < 26; k2++) {
                String result = affineDecrypt(cipher, k1, k2);
                // Simple check for common English words to highlight likely candidates
                if (result.contains("the") || result.contains("and") || result.contains("you")) {
                    System.out.printf("** (k1=%2d, k2=%2d): %s\n", k1, k2, result);
                }
            }
        }
        System.out.println("---------------------------------");
    }

    // ========================================================================
    // 4. AUTOKEY CIPHER (for Rustom/Kelvin problem)
    // ========================================================================

    /**
     * Encrypts plaintext using an Autokey Cipher.
     * Key = keyword + plaintext
     */
    public static String autokeyEncrypt(String text, String keyword) {
        text = cleanText(text, false);
        keyword = cleanText(keyword, false);
        String key = (keyword + text).substring(0, text.length());
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < text.length(); i++) {
            int p = text.charAt(i) - 'a';
            int k = key.charAt(i) - 'a';
            int ci = (p + k) % 26;
            sb.append((char) (ci + 'A'));
        }
        return sb.toString();
    }

    /**
     * Decrypts ciphertext from an Autokey Cipher.
     * We dynamically build the key as we decrypt.
     */
    public static String autokeyDecrypt(String cipher, String keyword) {
        cipher = cipher.toUpperCase();
        keyword = cleanText(keyword, false);
        StringBuilder sb = new StringBuilder();
        String key = keyword;

        for (int i = 0; i < cipher.length(); i++) {
            int ci = cipher.charAt(i) - 'A';
            int k;
            
            if (i < key.length()) {
                 k = key.charAt(i) - 'a';
            } else {
                // Key is now built from the plaintext we just decrypted
                k = sb.charAt(i - keyword.length()) - 'a';
            }

            int p = (ci - k) % 26;
            if (p < 0) {
                p += 26;
            }
            char plainChar = (char) (p + 'a');
            sb.append(plainChar);
        }
        return sb.toString();
    }
    // Note: Brute force for Autokey is not a simple loop. It requires
    // statistical analysis (e.g., Chi-squared) to guess the key length
    // and then the keyword. It's too complex for this demonstration.

    // ========================================================================
    // 5. PLAYFAIR CIPHER
    // ========================================================================

    private static char[][] playfairGrid;
    private static int[] charPos; // Stores [row, col] for each char

    /**
     * Generates the 5x5 Playfair grid from a keyword.
     * I and J are treated as the same.
     */
    public static void playfairGenerateGrid(String keyword) {
        playfairGrid = new char[5][5];
        charPos = new int[26]; // 0=A, 1=B, ... 25=Z
        keyword = cleanText(keyword, false).replaceAll("j", "i");
        String key = "";
        boolean[] added = new boolean[26];

        // Add keyword
        for (char c : keyword.toCharArray()) {
            if (!added[c - 'a']) {
                key += c;
                added[c - 'a'] = true;
            }
        }
        // Add remaining alphabet
        for (char c = 'a'; c <= 'z'; c++) {
            if (c == 'j') continue;
            if (!added[c - 'a']) {
                key += c;
                added[c - 'a'] = true;
            }
        }

        // Fill grid
        int k = 0;
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                playfairGrid[i][j] = key.charAt(k);
                int charIndex = key.charAt(k) - 'a';
                charPos[charIndex] = (i * 10) + j; // Store row/col as a single int
                if (key.charAt(k) == 'i') {
                    charPos['j' - 'a'] = (i * 10) + j; // J maps to I's position
                }
                k++;
            }
        }
    }

    /**
     * Prepares Playfair plaintext: (1) split into digraphs,
     * (2) add 'x' between doubles, (3) add 'x' if odd length.
     */
    private static String playfairPrepareText(String text) {
        text = cleanText(text, false).replaceAll("j", "i");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < text.length(); i += 2) {
            if (i + 1 == text.length()) {
                // Odd length, add 'x'
                sb.append(text.charAt(i)).append('x');
                break;
            }
            char c1 = text.charAt(i);
            char c2 = text.charAt(i + 1);
            if (c1 == c2) {
                // Double letter, add 'x' and step back
                sb.append(c1).append('x');
                i--; // Re-process from the second letter
            } else {
                sb.append(c1).append(c2);
            }
        }
        return sb.toString();
    }

    /**
     * Encrypts plaintext using the generated Playfair grid.
     */
    public static String playfairEncrypt(String text, String keyword) {
        playfairGenerateGrid(keyword);
        String preparedText = playfairPrepareText(text);
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < preparedText.length(); i += 2) {
            char c1 = preparedText.charAt(i);
            char c2 = preparedText.charAt(i + 1);
            
            int r1 = charPos[c1 - 'a'] / 10;
            int col1 = charPos[c1 - 'a'] % 10;
            int r2 = charPos[c2 - 'a'] / 10;
            int col2 = charPos[c2 - 'a'] % 10;

            char ec1, ec2;

            if (r1 == r2) { // Same row
                ec1 = playfairGrid[r1][(col1 + 1) % 5];
                ec2 = playfairGrid[r2][(col2 + 1) % 5];
            } else if (col1 == col2) { // Same column
                ec1 = playfairGrid[(r1 + 1) % 5][col1];
                ec2 = playfairGrid[(r2 + 1) % 5][col2];
            } else { // Rectangle
                ec1 = playfairGrid[r1][col2];
                ec2 = playfairGrid[r2][col1];
            }
            sb.append(ec1).append(ec2);
        }
        return sb.toString().toUpperCase();
    }

    /**
     * Decrypts ciphertext using the generated Playfair grid.
     */
    public static String playfairDecrypt(String cipher, String keyword) {
        playfairGenerateGrid(keyword);
        cipher = cleanText(cipher, false); // Keep it lowercase for charPos lookup
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < cipher.length(); i += 2) {
            char c1 = cipher.charAt(i);
            char c2 = cipher.charAt(i + 1);
            
            int r1 = charPos[c1 - 'a'] / 10;
            int col1 = charPos[c1 - 'a'] % 10;
            int r2 = charPos[c2 - 'a'] / 10;
            int col2 = charPos[c2 - 'a'] % 10;

            char dc1, dc2;

            if (r1 == r2) { // Same row
                dc1 = playfairGrid[r1][(col1 - 1 + 5) % 5];
                dc2 = playfairGrid[r2][(col2 - 1 + 5) % 5];
            } else if (col1 == col2) { // Same column
                dc1 = playfairGrid[(r1 - 1 + 5) % 5][col1];
                dc2 = playfairGrid[(r2 - 1 + 5) % 5][col2];
            } else { // Rectangle
                dc1 = playfairGrid[r1][col2];
                dc2 = playfairGrid[r2][col1];
            }
            sb.append(dc1).append(dc2);
        }
        return sb.toString();
    }

    // ========================================================================
    // 6. HILL CIPHER (2x2 implementation)
    // ========================================================================

    private static int[][] keyMatrix;
    private static int[][] invKeyMatrix;

    /**
     * Sets the 2x2 key matrix for Hill Cipher.
     */
    public static void hillSetKey(int[][] key) {
        keyMatrix = key;
        invKeyMatrix = hillFindInverse(key);
    }
    
    /**
     * Finds the modular inverse of a 2x2 matrix.
     */
    public static int[][] hillFindInverse(int[][] key) {
        int a = key[0][0], b = key[0][1], c = key[1][0], d = key[1][1];
        
        // det = (ad - bc) % 26
        int det = (a * d - b * c) % 26;
        if (det < 0) det += 26;

        int detInv = modInverse(det, 26);
        if (detInv == -1) {
            System.out.println("Key matrix is not invertible (mod 26).");
            return null;
        }

        int[][] inv = new int[2][2];
        // adj[0][0] = d
        // adj[0][1] = -b
        // adj[1][0] = -c
        // adj[1][1] = a
        
        inv[0][0] = ( d * detInv) % 26;
        inv[0][1] = (-b * detInv) % 26;
        inv[1][0] = (-c * detInv) % 26;
        inv[1][1] = ( a * detInv) % 26;

        // Fix negative values
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 2; j++) {
                if (inv[i][j] < 0) inv[i][j] += 26;
            }
        }
        return inv;
    }

    private static String hillProcess(String text, int[][] matrix) {
        text = cleanText(text, false);
        if (text.length() % 2 != 0) {
            text += 'x'; // Pad with 'x' if odd
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < text.length(); i += 2) {
            int p1 = text.charAt(i) - 'a';
            int p2 = text.charAt(i + 1) - 'a';

            int c1 = (matrix[0][0] * p1 + matrix[0][1] * p2) % 26;
            int c2 = (matrix[1][0] * p1 + matrix[1][1] * p2) % 26;

            sb.append((char) (c1 + 'A'));
            sb.append((char) (c2 + 'A'));
        }
        return sb.toString();
    }
    
    public static String hillEncrypt(String text, int[][] key) {
        hillSetKey(key);
        if (invKeyMatrix == null) return "ERROR: Key is not invertible.";
        String cipher = hillProcess(text, keyMatrix);
        
        // Show key and inverse as requested
        System.out.println("\n--- Hill Cipher Key Info ---");
        System.out.println("Key Matrix:");
        System.out.println(Arrays.toString(keyMatrix[0]));
        System.out.println(Arrays.toString(keyMatrix[1]));
        System.out.println("Key Inverse Matrix:");
        System.out.println(Arrays.toString(invKeyMatrix[0]));
        System.out.println(Arrays.toString(invKeyMatrix[1]));
        System.out.println("----------------------------");
        
        return cipher;
    }

    public static String hillDecrypt(String cipher) {
        if (invKeyMatrix == null) {
            return "ERROR: No inverse key matrix set. Encrypt first or set key.";
        }
        // Decryption needs lowercase input for processing
        String text = hillProcess(cipher.toLowerCase(), invKeyMatrix);
        return text;
    }

    // ========================================================================
    // 7. ELGAMAL CRYPTOSYSTEM
    // ========================================================================

    public static class ElGamalKeys {
        BigInteger p, g, y; // Public Key (p, g, y)
        BigInteger x;       // Private Key (x)
    }

    public static class ElGamalCipher {
        BigInteger c1, c2;
    }

    private static final BigInteger ELG_P = new BigInteger("2357"); // A small prime
    private static final BigInteger ELG_G = new BigInteger("2");    // A generator

    public static ElGamalKeys elGamalGenerateKeys() {
        ElGamalKeys keys = new ElGamalKeys();
        keys.p = ELG_P;
        keys.g = ELG_G;
        // Private key x: 1 < x < p-1
        keys.x = new BigInteger(keys.p.bitLength() - 1, new Random());
        while (keys.x.compareTo(BigInteger.ONE) <= 0) {
             keys.x = new BigInteger(keys.p.bitLength() - 1, new Random());
        }
        // Public key y = g^x mod p
        keys.y = keys.g.modPow(keys.x, keys.p);
        return keys;
    }

    public static ElGamalCipher elGamalEncrypt(BigInteger m, ElGamalKeys pubKey) {
        ElGamalCipher cipher = new ElGamalCipher();
        // Ephemeral key k: 1 < k < p-1
        BigInteger k = new BigInteger(pubKey.p.bitLength() - 1, new Random());
         while (k.compareTo(BigInteger.ONE) <= 0) {
             k = new BigInteger(pubKey.p.bitLength() - 1, new Random());
        }
        // c1 = g^k mod p
        cipher.c1 = pubKey.g.modPow(k, pubKey.p);
        // c2 = (m * y^k) mod p
        cipher.c2 = m.multiply(pubKey.y.modPow(k, pubKey.p)).mod(pubKey.p);
        return cipher;
    }

    public static BigInteger elGamalDecrypt(ElGamalCipher cipher, ElGamalKeys keys) {
        // M = (c2 * (c1^x)^-1) mod p
        // (c1^x)^-1 is c1.modPow(p-1-x, p)
        BigInteger c1x_inv = cipher.c1.modPow(keys.p.subtract(BigInteger.ONE).subtract(keys.x), keys.p);
        // M = (c2 * c1x_inv) mod p
        BigInteger m = cipher.c2.multiply(c1x_inv).mod(keys.p);
        return m;
    }

    // ========================================================================
    // 8. RABIN-MILLER PRIMALITY TEST
    // ========================================================================

    /**
     * Checks if n is probably prime using k rounds of Rabin-Miller.
     * @param n The number to test.
     * @param k The number of rounds (accuracy).
     * @return true if probably prime, false if composite.
     */
    public static boolean isProbablyPrime(BigInteger n, int k) {
        if (n.compareTo(BigInteger.ONE) <= 0) return false;
        if (n.compareTo(BigInteger.valueOf(3)) <= 0) return true;
        if (n.mod(BigInteger.TWO).equals(BigInteger.ZERO)) return false;

        // Write n-1 as 2^r * d
        BigInteger d = n.subtract(BigInteger.ONE);
        int r = 0;
        while (d.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            d = d.divide(BigInteger.TWO);
            r++;
        }

        Random rand = new Random();
        for (int i = 0; i < k; i++) {
            // Pick a random 'a' in [2, n-2]
            BigInteger a;
            do {
                a = new BigInteger(n.bitLength(), rand);
            } while (a.compareTo(BigInteger.TWO) < 0 || a.compareTo(n.subtract(BigInteger.TWO)) > 0);

            // x = a^d % n
            BigInteger x = a.modPow(d, n);

            if (x.equals(BigInteger.ONE) || x.equals(n.subtract(BigInteger.ONE))) {
                continue; // Probably prime, next round
            }
            
            boolean composite = true;
            for (int j = 0; j < r - 1; j++) {
                x = x.modPow(BigInteger.TWO, n);
                if (x.equals(n.subtract(BigInteger.ONE))) {
                    composite = false;
                    break; // Probably prime, next round
                }
            }

            if (composite) {
                return false; // Definitely composite
            }
        }
        return true; // Probably prime
    }
    
    // ========================================================================
    // 9. DIFFIE-HELLMAN KEY EXCHANGE
    // ========================================================================

    public static class DH_Participant {
        BigInteger p, g;       // Public params
        BigInteger privateKey;
        BigInteger publicKey;
        BigInteger sharedSecret;

        public DH_Participant(BigInteger p, BigInteger g) {
            this.p = p;
            this.g = g;
            // privateKey: 1 < x < p-1
            this.privateKey = new BigInteger(p.bitLength() - 1, new Random());
             while (this.privateKey.compareTo(BigInteger.ONE) <= 0) {
                 this.privateKey = new BigInteger(p.bitLength() - 1, new Random());
            }
            // publicKey = g^privateKey mod p
            this.publicKey = g.modPow(this.privateKey, p);
        }
        
        public void generateSharedSecret(BigInteger otherPublicKey) {
            // sharedSecret = otherPublicKey^privateKey mod p
            this.sharedSecret = otherPublicKey.modPow(this.privateKey, p);
        }
    }

    // ========================================================================
    // 10. RSA CRYPTOSYSTEM
    // ========================================================================
    
    public static class RSAKeys {
        BigInteger e, d, n; // e,n = public; d,n = private
    }

    public static RSAKeys rsaGenerateKeys(BigInteger p, BigInteger q) {
        RSAKeys keys = new RSAKeys();
        keys.n = p.multiply(q);
        // phi(n) = (p-1)(q-1)
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        
        // e = 65537 (common public exponent)
        keys.e = new BigInteger("65537"); 
        
        // d = e^-1 mod phi
        keys.d = keys.e.modInverse(phi);
        
        return keys;
    }

    // Note: RSA encrypts/decrypts numbers, not strings.
    // We use BigInteger.getBytes() / new BigInteger(bytes) for demo.
    
    public static BigInteger rsaEncrypt(BigInteger m, BigInteger e, BigInteger n) {
        // C = M^e mod n
        return m.modPow(e, n);
    }
    
    public static BigInteger rsaDecrypt(BigInteger c, BigInteger d, BigInteger n) {
        // M = C^d mod n
        return c.modPow(d, n);
    }
    
    // ========================================================================
    // 11. RSA DIGITAL SIGNATURE
    // ========================================================================

    /**
     * Creates a hash (SHA-256) of a message.
     */
    private static BigInteger hashMessage(String message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = md.digest(message.getBytes());
        // Turn hash into a positive BigInteger
        return new BigInteger(1, hashBytes);
    }

    /**
     * Signs a message by hashing it and encrypting the hash with the private key.
     * @param message The message to sign.
     * @param d The private exponent.
     * @param n The modulus.
     * @return The signature as a BigInteger.
     */
    public static BigInteger rsaSign(String message, BigInteger d, BigInteger n) 
        throws NoSuchAlgorithmException {
        BigInteger hash = hashMessage(message);
        // Signature = Hash^d mod n
        return hash.modPow(d, n);
    }

    /**
     * Verifies a signature.
     * @param message The original message.
     * @param signature The signature to check.
     * @param e The public exponent.
     * @param n The modulus.
     * @return true if the signature is valid, false otherwise.
     */
    public static boolean rsaVerify(String message, BigInteger signature, BigInteger e, BigInteger n) 
        throws NoSuchAlgorithmException {
        // Decrypt signature with public key
        // DecryptedHash = Signature^e mod n
        BigInteger decryptedHash = signature.modPow(e, n);
        
        // Hash the original message
        BigInteger originalHash = hashMessage(message);
        
        // Compare
        return originalHash.equals(decryptedHash);
    }
    

    // ========================================================================
    // MAIN METHOD TO DEMONSTRATE ALL 11 PROBLEMS
    // ========================================================================
    public static void main(String[] args) {

        System.out.println("====== CRYPTOGRAPHY LAB SOLUTIONS ======\n");
        
        // --- 1. Shift Cipher ---
        System.out.println("--- Problem 1: Shift Cipher ---");
        String p1 = "attackatdawn";
        int k1 = 5;
        String c1 = shiftEncrypt(p1, k1);
        System.out.println("Plaintext:  " + p1);
        System.out.println("Ciphertext: " + c1);
        System.out.println("Decrypted:  " + shiftDecrypt(c1, k1));
        shiftBruteForce(c1);

        // --- 2. Multiplicative Cipher ---
        System.out.println("\n--- Problem 2: Multiplicative Cipher ---");
        String p2 = "multiplicative";
        int k2 = 7;
        String c2 = multiplicativeEncrypt(p2, k2);
        System.out.println("Plaintext:  " + p2);
        System.out.println("Key: " + k2);
        System.out.println("Ciphertext: " + c2);
        System.out.println("Decrypted:  " + multiplicativeDecrypt(c2, k2));
        multiplicativeBruteForce(c2);

        // --- 3. Affine Cipher ---
        System.out.println("\n--- Problem 3: Affine Cipher ---");
        String p3 = "affinecipher";
        int k3_1 = 5; // k1 (multiplicative)
        int k3_2 = 8; // k2 (shift)
        String c3 = affineEncrypt(p3, k3_1, k3_2);
        System.out.println("Plaintext:  " + p3);
        System.out.println("Keys: k1=" + k3_1 + ", k2=" + k3_2);
        System.out.println("Ciphertext: " + c3);
        System.out.println("Decrypted:  " + affineDecrypt(c3, k3_1, k3_2));
        affineBruteForce(c3);

        // --- 4. Autokey Cipher (Rustom/Kelvin) ---
        System.out.println("\n--- Problem 4: Autokey Cipher (Rustom/Kelvin) ---");
        String p4 = "meetmeaftertogaparty";
        String k4 = "rustom";
        String c4 = autokeyEncrypt(p4, k4);
        System.out.println("Message:   " + p4);
        System.out.println("Keyword:   " + k4);
        System.out.println("Ciphertext:" + c4);
        System.out.println("Decrypted: " + autokeyDecrypt(c4, k4));
        System.out.println("(Brute force for autokey is non-trivial and omitted)");

        // --- 5. Playfair Cipher ---
        System.out.println("\n--- Problem 5: Playfair Cipher ---");
        String p5 = "hidethegoldinthetreestump";
        String k5 = "keyword"; // As per your example
        String c5 = playfairEncrypt(p5, k5);
        System.out.println("Message:   " + p5);
        System.out.println("Keyword:   " + k5);
        System.out.println("Ciphertext:" + c5);
        System.out.println("Decrypted: " + playfairDecrypt(c5, k5));

        // --- 6. Hill Cipher ---
        System.out.println("\n--- Problem 6: Hill Cipher ---");
        String p6 = "help";
        // Key matrix: {{9, 4}, {5, 7}}
        int[][] k6 = { {9, 4}, {5, 7} };
        String c6 = hillEncrypt(p6, k6);
        System.out.println("Plaintext:  " + p6);
        System.out.println("Ciphertext: " + c6);
        System.out.println("Decrypted:  " + hillDecrypt(c6));
        
        // --- 7. ElGamal Cryptosystem ---
        System.out.println("\n--- Problem 7: ElGamal Cryptosystem ---");
        ElGamalKeys elgKeys = elGamalGenerateKeys();
        System.out.println("ElGamal Public (p, g, y): (" + elgKeys.p + ", " + elgKeys.g + ", " + elgKeys.y + ")");
        System.out.println("ElGamal Private (x): (" + elgKeys.x + ")");
        BigInteger m7 = new BigInteger("1234"); // Message as a number
        System.out.println("Original Message: " + m7);
        ElGamalCipher c7 = elGamalEncrypt(m7, elgKeys);
        System.out.println("Ciphertext (c1, c2): (" + c7.c1 + ", " + c7.c2 + ")");
        BigInteger d7 = elGamalDecrypt(c7, elgKeys);
        System.out.println("Decrypted Message: " + d7);

        // --- 8. Rabin-Miller Primality Test ---
        System.out.println("\n--- Problem 8: Rabin-Miller Primality Test ---");
        BigInteger primeTest = new BigInteger("170141183460469231731687303715884105727"); // A large prime
        BigInteger compositeTest = new BigInteger("170141183460469231731687303715884105729"); // (prime + 2)
        System.out.println("Is " + primeTest + " prime? " + (isProbablyPrime(primeTest, 20) ? "Probably Yes" : "No"));
        System.out.println("Is " + compositeTest + " prime? " + (isProbablyPrime(compositeTest, 20) ? "Probably Yes" : "No"));

        // --- 9. Diffie-Hellman Key Exchange ---
        System.out.println("\n--- Problem 9: Diffie-Hellman Key Exchange ---");
        BigInteger dh_p = ELG_P; // Use the same prime from ElGamal for simplicity
        BigInteger dh_g = ELG_G;
        
        DH_Participant alice = new DH_Participant(dh_p, dh_g);
        DH_Participant bob = new DH_Participant(dh_p, dh_g);
        
        System.out.println("Alice's Public Key: " + alice.publicKey);
        System.out.println("Bob's Public Key:   " + bob.publicKey);
        
        // They exchange keys and generate the shared secret
        alice.generateSharedSecret(bob.publicKey);
        bob.generateSharedSecret(alice.publicKey);
        
        System.out.println("Alice's Shared Secret: " + alice.sharedSecret);
        System.out.println("Bob's Shared Secret:   " + bob.sharedSecret);
        System.out.println("Secrets Match: " + alice.sharedSecret.equals(bob.sharedSecret));
        
        // Now, use this shared key to encrypt/decrypt (using Shift Cipher for demo)
        int sharedKey = alice.sharedSecret.mod(BigInteger.valueOf(26)).intValue();
        System.out.println("Using shared key for Shift Cipher (key = " + sharedKey + ")");
        String p9 = "secretmessage";
        String c9 = shiftEncrypt(p9, sharedKey);
        System.out.println("Plaintext:  " + p9);
        System.out.println("Ciphertext: " + c9);
        System.out.println("Decrypted:  " + shiftDecrypt(c9, sharedKey));

        // --- 10. RSA Cryptosystem ---
        System.out.println("\n--- Problem 10: RSA Cryptosystem ---");
        // Use small, simple primes for demo. Real RSA uses 2048-bit primes.
        BigInteger p10 = new BigInteger("61");
        BigInteger q10 = new BigInteger("53");
        RSAKeys rsaKeys = rsaGenerateKeys(p10, q10);
        System.out.println("RSA Public Key (e, n): (" + rsaKeys.e + ", " + rsaKeys.n + ")");
        System.out.println("RSA Private Key (d, n): (" + rsaKeys.d + ", " + rsaKeys.n + ")");
        
        BigInteger m10 = new BigInteger("688"); // Message "HI" (6, 8) -> 6*26+8 = 164? No, just a number.
        System.out.println("Original Message: " + m10);
        BigInteger c10 = rsaEncrypt(m10, rsaKeys.e, rsaKeys.n);
        System.out.println("Ciphertext: " + c10);
        BigInteger d10 = rsaDecrypt(c10, rsaKeys.d, rsaKeys.n);
        System.out.println("Decrypted Message: " + d10);

        // --- 11. RSA Digital Signature ---
        System.out.println("\n--- Problem 11: RSA Digital Signature ---");
        try {
            String msg = "This is an example";
            System.out.println("Original Message: " + msg);
            
            // Alice signs with her private key (d, n)
            BigInteger signature = rsaSign(msg, rsaKeys.d, rsaKeys.n);
            System.out.println("Signature: " + signature);
            
            // Bob verifies with Alice's public key (e, n)
            boolean isValid = rsaVerify(msg, signature, rsaKeys.e, rsaKeys.n);
            System.out.println("Signature is valid: " + isValid);
            
            // Tamper the message
            String tamperedMsg = "This is an example!";
            System.out.println("\nVerifying with tampered message: " + tamperedMsg);
            boolean isTamperedValid = rsaVerify(tamperedMsg, signature, rsaKeys.e, rsaKeys.n);
            System.out.println("Signature is valid: " + isTamperedValid);

        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error: SHA-256 algorithm not found.");
            e.printStackTrace();
        }
    }
}