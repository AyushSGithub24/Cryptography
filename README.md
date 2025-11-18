# A Simple Guide to Your Cryptography Algorithms

You've got a list of 11 problems in cryptography. Let's walk through what each one is _actually_ doing,
without the scary math terms.

1. Shift Cipher (or Caesar Cipher)
    The Big Idea: This is the "decoder ring" you'd get in a cereal box.
    Simple Analogy: Imagine the alphabet written on a paper wheel, and another one inside it. To
    "encrypt," you just _shift_ the inner wheel by a secret number (the "key").
    How it Works:
       You pick a secret key, say, 3.
          A becomes D (A + 3 = D)
          B becomes E (B + 3 = E)
          HELLO becomes KHOOR.
    Decryption: You just shift back by 3. KHOOR becomes HELLO.
    Brute Force: Since there are only 26 letters, there are only 25 useful keys (a key of 26 is the same
    as a key of 0). To "brute force" it, you just try all 25 possible shifts until one of them makes sense.
2. Multiplicative Cipher
    The Big Idea: Instead of _sliding_ the alphabet, you _jump_ through it.
    How it Works:
       You give each letter a number (A=0, B=1, ... Z=25).
       You pick a secret key (a number), say 7.
       You _multiply_ the letter's number by the key.
          B is 1. 1 * 7 = 7. 7 is H. So, B becomes H.
          D is 3. 3 * 7 = 21. 21 is V. So, D becomes V.
    Key Constraint: The "key" _must_ be a number that is coprime with 26. This is a fancy way of-
    saying it doesn't share any factors with 26 (other than 1). This is to make sure you can always
    decrypt it. If you used 2 as a key, both A (0) and M (12) would become A (0 * 2 = 0, 12 * 2 =
    24... oh wait, 24 is Y. Bad example. A(0) and N(13). A -> 0 * 2 = 0 (A). N -> 13 * 2 = 26,
    which is 0 (A). Both A and N become A. You can't decrypt that!). The valid keys are {1, 3, 5, 7,
    9, 11, 15, 17, 19, 21, 23, 25}.
    Decryption: You need a "magic reverse number" called a _modular multiplicative inverse_. It's the
    number that, when multiplied by your key, gets you back to 1. For our key 7 , the inverse is 15
    (because 7 * 15 = 105, and 105 % 26 = 1).


```
Brute Force: You just try all 12 of the valid keys.
```
3. Affine Cipher
    The Big Idea: This cipher just does _both_ of the first two.
    How it Works: It uses _two keys_.
       1. First, you _multiply_ by key1 (like the Multiplicative Cipher).
       2. Then, you _add_ key2 (like the Shift Cipher).
          Formula: Cipher = (Plaintext * key1 + key2) % 26
    Key Constraints: key1 must be one of the 12 "coprime" keys. key2 can be any number from 0
    to 25.
    Security: This is stronger than the first two, but still very weak.
    Brute Force: You just try all possible pairs of keys. There are 12 choices for key1 and 26 for
       key2, so 12 * 26 = 312 total guesses. A computer can do this instantly.
4. Autokey Cipher (Vigenère family)
    The Big Idea: The problem describes a polyalphabetic cipher. The "initial key" is a keyword, and
    the "other keys are generated automatically" by using the _plaintext message itself_ as the rest of
    the key. This is the Autokey Cipher.
    How it Works: This is a Shift Cipher where the _shift amount changes for every letter_.
       Message: MEET ME AFTER TOGA PARTY
       Keyword: RUSTOM
       Autokey: RUSTOM**MEETMEAFTERTOGAP** (The key starts with RUSTOM, then is extended by
       the message MEETME...)
       Now you encrypt one letter at a time, using the corresponding key letter as the "shift amount".
          M (12) + R (17) = 29 % 26 = 3 (D)
          E (4) + U (20) = 24 % 26 = 24 (Y)
          E (4) + S (18) = 22 % 26 = 22 (W)
       ...and so on.
    Security: This is _much_ stronger than the first three because the same letter (E) encrypts to a
    different letter each time (Y and W in our example). This breaks simple "frequency analysis"
    (where E is the most common letter).
    Brute Force: A "brute force" in the same way (trying all keys) is not possible, as the key is as long
    as the message. An attacker would have to guess the _keyword_ and its _length_ , which is much,
    much harder.
5. Playfair Cipher


```
The Big Idea: Encrypts pairs of letters at a time, using a 5x5 grid.
How it Works:
```
1. Create a 5x5 Grid: You fill a 5x5 grid with a keyword (no repeating letters), then fill the rest
    with the alphabet. Since there are 25 squares, I and J are put in the _same square_.
2. Prepare the Message: Break the message into pairs of letters (ME ET ME AF TE RT OG AP
    AR TY).
       If a pair has the same letter (like HELLO -> HE LL O), add an X: HE LX LO.
       If there's an odd letter at the end, add an X: HE LX LO XZ.
3. Encrypt the Pairs: Find the two letters in your grid and follow 3 rules:
    Same Row: Take the letters to their _right_ (wrap around).
    Same Column: Take the letters _below_ them (wrap around).
    Rectangle: Form a rectangle. Take the letters at the _other two corners_ (on the same row).
Security: Even stronger. It hides single-letter frequencies and encrypts 600+ possible pairs ( 25
* 24), not just 26 letters.
6. Hill Cipher
The Big Idea: Uses "matrix math" to encrypt blocks of letters.
How it Works:
1. You pick a key matrix (e.g., a 2x2 grid of numbers).
2. You turn your message into pairs of numbers (vectors). HI -> [7, 8].
3. You use matrix multiplication: Key_Matrix * [7, 8] = [New_Num1, New_Num2].
4. These new numbers are your ciphertext letters.
Decryption: You need the inverse of your key matrix. You multiply the ciphertext vectors by this
"reverse matrix" to get the plaintext back.
Security: Very strong... _if_ the key is big (e.g., 3x3 or 4x4). It encrypts multiple letters at once,
completely scrambling the language patterns. Its weakness is that it's vulnerable to a "known-
plaintext attack" (if you know some of the original message, you can solve for the matrix).
7. ElGamal Cryptosystem
The Big Idea: This is a "two-key" system, also called Asymmetric Cryptography.
Simple Analogy: Imagine you have a special public padlock. You can make copies and give them
to _everyone_. Anyone can use your padlock to lock a box. But _only you_ have the private key that
can open it.


```
How itWorks:
Key Generation: You pick a giant private number x and do some hard math to create a
public number y.
Public Key: (y, g, p) - You post this on the internet.
Private Key: (x) - You never tell anyone this.
Encryption: Alice uses your public key to turn her message M into two ciphertext numbers,
C1 and C2.
Decryption: You use your private key x with C1 and C2 to get M back.
Security: Based on a "hard problem" called the Discrete Logarithm Problem. It's easy to do
g^x to get y, but it's impossibly hard for a computer to find x if they only know y, g, and
p.
```
8. Rabin-Miller Primality Test
    The Big Idea: A way to check if a _gigantic_ number is prime (only divisible by 1 and itself).
    Why? All modern crypto (like ElGamal, RSA) _needs_ giant prime numbers.
    How it Works: You can't just try dividing. A 200-digit number would take longer than the age of
    the universe to check.
    Simple Analogy: It's a "spot check." Imagine you're a bouncer at a club for "Prime Numbers
    Only." Instead of a full body search (trial division), you ask a few _very clever_ questions.
       If the number _fails_ even one question, you know _for sure_ it's "composite" (not prime) and you
       kick it out.
       If it _passes_ all (say) 20 questions, you can't be 100% sure, but you are _so_ sure (like
       99.999...9%) that it's prime, you let it in.
    This is a probabilistic test. It's not a "yes/no," it's a "definitely no" or a "very, _very_ probably yes."
9. Diffie-Hellman Key Exchange
    The Big Idea: A "magic trick" for two people (Alice and Bob) to _create a shared secret key_ over a
    public channel (where an enemy, Eve, is listening) without _ever sending the key_.

```
Shutterstock
```

```
This is NOT encryption. It's a way to agree on a key to use for other encryption (like a Shift
Cipher, but with a huge key).
Simple Analogy (The Paint Mixing Trick):
```
1. Public: Alice and Bob agree on a "public" paint color: Yellow.
2. Private: Alice picks a _secret_ color (Red). Bob picks a _secret_ color (Blue).
3. Exchange:
    Alice mixes Yellow + Red to get Orange. She sends Orange to Bob.
    Bob mixes Yellow + Blue to get Green. He sends Green to Alice.
4. Eve Sees: The listener (Eve) sees Orange and Green go by, but not the secret colors (Red or
    Blue).
5. Create Secret:
    Alice gets Green and mixes in her _secret_ color (Red). Green + Red = (Yellow + Blue)
    + Red = **Brown**.
    Bob gets Orange and mixes in his _secret_ color (Blue). Orange + Blue = (Yellow +
    Red) + Blue = **Brown**.
6. Result: Both Alice and Bob have the _exact same_ secret color (Brown), and Eve has no idea
    what it is!
The "paint" is math with giant numbers (g^a mod p).
10. RSA Algorithm (Rivest–Shamir–Adleman)
The Big Idea: The _most famous_ two-key (asymmetric) system.
How it Works:
1. Key Generation:
Alice secretly picks two _huge_ prime numbers, p and q. (She uses Rabin-Miller to find
them!)
She multiplies them: n = p * q.
She does some math to get her Public Key (e, n) and her Private Key (d, n).
2. Encryption: Bob wants to send "HELLO" to Alice.
He looks up her Public Key (e, n).
He runs the message through the formula: Cipher = (Message)^e mod n.
3. Decryption: Alice gets the ciphertext.
She uses her Private Key (d, n).
Formula: Message = (Cipher)^d mod n.
Security: Based on the Factoring Problem. It's easy to multiply p and q to get n. But if n is
600 digits long, it is _impossible_ for anyone to find the original p and q. Your private key d


```
depends on p and q, so only you (who made them) can have it.
```
11. RSA Digital Signature
    The Big Idea: Uses RSA "in reverse" to _prove_ a message came from you and wasn't changed. This
    is for Authentication, not Secrecy.
    Simple Analogy: A "digital wax seal."
    How it Works:
       1. Alice signs:
          She writes her message: "This is an example".
          She creates a "fingerprint" of the message called a hash (a short, unique string, like
             a5f8...).
          She "encrypts" the _hash_ with her PRIVATE KEY. This is the signature.
       2. Alice sends: The (plain, unencrypted) message + the signature.
       3. Bob verifies:
          He gets the message and the signature.
          He creates his _own_ hash of the message.
          He "decrypts" the signature using Alice's PUBLIC KEY.
       4. Compare: If his hash matches the decrypted signature, he knows two things:
          It's from Alice: Only her private key could have created a signature that her public key
          could open.

```
Shutterstock
```

