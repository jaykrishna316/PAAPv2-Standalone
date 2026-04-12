const { hexToBigInt } = require('./bigint');

// RFC 3526 "MODP Group 14" (2048-bit prime), as returned by Node's crypto.getDiffieHellman('modp14').
// Keeping this in-code avoids a runtime dependency and keeps browser/server aligned.
const MODP14_PRIME_HEX =
  'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff';

const MODP14_GENERATOR_HEX = '02';

const P = hexToBigInt(MODP14_PRIME_HEX);
const G = hexToBigInt(MODP14_GENERATOR_HEX);
const Q = (P - 1n) / 2n; // safe prime: p = 2q + 1

function padHexToBytes(hex, bytes) {
  const normalized = hex.startsWith('0x') ? hex.slice(2) : hex;
  return normalized.padStart(bytes * 2, '0');
}

function bigIntToFixedHex(value, bytes) {
  let hex = value.toString(16);
  if (hex.length % 2 === 1) hex = '0' + hex;
  return padHexToBytes(hex, bytes);
}

function getModp14() {
  return {
    id: 'modp14',
    primeHex: MODP14_PRIME_HEX,
    generatorHex: MODP14_GENERATOR_HEX,
    p: P,
    q: Q,
    g: G,
    elementBytes: 256,
    bigIntToFixedHex
  };
}

module.exports = {
  getModp14
};

