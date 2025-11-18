import java.util.*;
public class RSA {

    static int gcd(int a, int b) {
        while (b != 0) {
            int temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

    static int modInverse(int e, int phi) {
        e = e % phi;
        for (int d = 1; d < phi; d++) {
            if ((e * d) % phi == 1)
                return d;
        }
        return -1;
    }

    static int modPow(int base, int exp, int mod) {
        int result = 1;
        base = base % mod;
        for (int i = 0; i < exp; i++) {
            result = (result * base) % mod;
        }
        return result;
    }

    public static void main(String[] args) {
        
        Scanner sc = new Scanner(System.in);
        
        IO.print("Enter p and q");
      
        
        int p = sc.nextInt();
        int q = sc.nextInt();

        int n = p * q;               
        int phi = (p - 1) * (q - 1); 

        System.out.println("values of e:");
        int e = sc.nextInt();
        while (gcd(e, phi) != 1) e++;

          System.out.println("Enter plain text:");
        int message = sc.nextInt();  

        int d = modInverse(e, phi);

        System.out.println("Public key: (e = " + e + ", n = " + n + ")");
        System.out.println("Private key: (d = " + d + ", n = " + n + ")");
        
        
        System.out.println("\nOriginal Message: " + message);

        // Step 6: Encryption
        int ciphertext = modPow(message, e, n);
        System.out.println("ciphertext: " + ciphertext);

        // Step 7: Decryption
        int decrypted = modPow(ciphertext, d, n);
        System.out.println("Decryptedtext: " + decrypted);
    }
}