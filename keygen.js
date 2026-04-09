/**
 * ELGAMAL ASYMMETRIC KEY GENERATOR
 * This script generates the cryptographic foundation for the Feedback Vault.
 * Architecture: Asymmetric (Public-Key) Cryptography
 */

const crypto = require('crypto');

/**
 * FUNCTION: power(base, exp, mod)
 * Implementation: Binary Exponentiation (Exponentiation by Squaring)
 * * Why it's needed: Standard Math.pow() cannot handle the 512-bit numbers 
 * required for security. This function efficiently calculates (base^exp % mod)
 * without creating numbers so large they crash the memory.
 * * Time Complexity: O(log exp)
 */
function power(base, exp, mod) {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
        // If the exponent bit is 1, multiply the result by the current base
        if (exp % 2n === 1n) result = (result * base) % mod;

        // Square the base and move to the next bit of the exponent
        base = (base * base) % mod;
        exp = exp / 2n;
    }
    return result;
}

/**
 * ELGAMAL PARAMETERS
 * * p: A large prime number. This defines the "Safe Prime" group where 
 * the math takes place. It must be large enough to make the 
 * Discrete Logarithm Problem computationally "hard" to solve.
 * * g: The Generator. A number that, when raised to different powers 
 * modulo p, can generate elements of the group.
 */
const p = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171n;
const g = 2n;

/**
 * STEP 1: GENERATE PRIVATE KEY (x)
 * We generate 64 random bytes (512 bits) of entropy.
 * The private key must be a random integer in the range [1, p-2].
 * * Role: This key is used in your server.js to decrypt the ciphertext (c1, c2).
 * Mathematically: s = c1^x mod p
 */
const x = BigInt('0x' + crypto.randomBytes(64).toString('hex')) % (p - 2n) + 1n;

/**
 * STEP 2: GENERATE PUBLIC KEY (y)
 * Calculated using the formula: y = g^x mod p
 * * Role: This is used during encryption to hide the message.
 * It is computationally impossible for someone to figure out 'x' 
 * even if they know 'y', 'g', and 'p'.
 */
const y = power(g, x, p);

// Output the keys for environment configuration
console.log('\n===== YOUR ELGAMAL KEY PAIR =====\n');
console.log('ELGAMAL_P =', p.toString());
console.log('ELGAMAL_G =', g.toString());
console.log('ELGAMAL_X =', x.toString(), ' ← 🔴 PRIVATE KEY — never share this');
console.log('ELGAMAL_Y =', y.toString());
console.log('\n=================================');

/**
 * RELEVANT OPERATIONS SUMMARY:
 * * ENCRYPTION (In your feedback submission):
 * 1. Convert text message to number 'm'.
 * 2. Choose random ephemeral key 'k'.
 * 3. Calculate ciphertext part 1: c1 = g^k mod p.
 * 4. Calculate ciphertext part 2: c2 = (m * y^k) mod p.
 * * DECRYPTION (In your Admin Vault):
 * 1. Use private key 'x' to recover shared secret: s = c1^x mod p.
 * 2. Calculate modular inverse of 's' (sInv).
 * 3. Recover original message: m = (c2 * sInv) mod p.
 */

console.log('✅ Copy these into your Render environment variables.');
console.log('⚠️  Delete this file or keep it offline after use.\n');
