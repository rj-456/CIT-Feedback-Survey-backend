const crypto = require('crypto');

function power(base, exp, mod) {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
        if (exp % 2n === 1n) result = (result * base) % mod;
        base = (base * base) % mod;
        exp = exp / 2n;
    }
    return result;
}

const p = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171n;
const g = 2n;

const x = BigInt('0x' + crypto.randomBytes(64).toString('hex')) % (p - 2n) + 1n;
const y = power(g, x, p);

console.log('\n===== YOUR ELGAMAL KEY PAIR =====\n');
console.log('ELGAMAL_P =', p.toString());
console.log('ELGAMAL_G =', g.toString());
console.log('ELGAMAL_X =', x.toString(), ' ← 🔴 PRIVATE KEY — never share this');
console.log('ELGAMAL_Y =', y.toString());
console.log('\n=================================');
console.log('✅ Copy these into your Render environment variables.');
console.log('⚠️  Delete this file or keep it offline after use.\n');