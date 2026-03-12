import { randomBytes, randomInt } from "node:crypto";

/**
 * Shamir Secret Sharing over GF(2^8)
 * Ported from HashiCorp Vault's shamir/shamir.go (MPL-2.0)
 *
 * Splits a secret into N shares where any T (threshold) shares
 * can reconstruct the original secret via Lagrange interpolation.
 */

const SHARE_OVERHEAD = 1;

// GF(2^8) addition is XOR (also subtraction, since symmetric)
function add(a: number, b: number): number {
  return a ^ b;
}

// GF(2^8) multiplication using Russian Peasant algorithm with reduction polynomial 0x1B (AES)
function mult(a: number, b: number): number {
  let r = 0;
  for (let i = 7; i >= 0; i--) {
    r = ((-((b >> i) & 1) & a) ^ (-((r >> 7) & 1) & 0x1b) ^ (r + r)) & 0xff;
  }
  return r;
}

// GF(2^8) multiplicative inverse via repeated squaring (Fermat's little theorem: a^254 = a^-1)
function inverse(a: number): number {
  let b = mult(a, a);
  let c = mult(a, b);
  b = mult(c, c);
  b = mult(b, b);
  c = mult(b, c);
  b = mult(b, b);
  b = mult(b, b);
  b = mult(b, c);
  b = mult(b, b);
  b = mult(a, b);
  return mult(b, b);
}

// GF(2^8) division with constant-time zero check
function div(a: number, b: number): number {
  if (b === 0) {
    throw new Error("shamir: divide by zero");
  }
  const ret = mult(a, inverse(b));
  // Return 0 if a is 0 (constant-time select)
  return a === 0 ? 0 : ret;
}

// Polynomial with coefficients in GF(2^8)
interface Polynomial {
  coefficients: Uint8Array;
}

function makePolynomial(intercept: number, degree: number): Polynomial {
  const coefficients = new Uint8Array(degree + 1);
  coefficients[0] = intercept;

  // Fill remaining coefficients with cryptographic randomness
  const rand = randomBytes(degree);
  for (let i = 0; i < degree; i++) {
    coefficients[i + 1] = rand[i];
  }

  return { coefficients };
}

// Evaluate polynomial at x using Horner's method
function evaluate(p: Polynomial, x: number): number {
  if (x === 0) {
    return p.coefficients[0];
  }

  const degree = p.coefficients.length - 1;
  let out = p.coefficients[degree];
  for (let i = degree - 1; i >= 0; i--) {
    out = add(mult(out, x), p.coefficients[i]);
  }
  return out;
}

// Lagrange interpolation at target x given sample points
function interpolatePolynomial(xSamples: Uint8Array, ySamples: Uint8Array, x: number): number {
  const limit = xSamples.length;
  let result = 0;

  for (let i = 0; i < limit; i++) {
    let basis = 1;
    for (let j = 0; j < limit; j++) {
      if (i === j) continue;
      const num = add(x, xSamples[j]);
      const denom = add(xSamples[i], xSamples[j]);
      basis = mult(basis, div(num, denom));
    }
    result = add(result, mult(ySamples[i], basis));
  }
  return result;
}

// Fisher-Yates shuffle to generate random permutation of [0..n-1]
function randomPerm(n: number): number[] {
  const arr = Array.from({ length: n }, (_, i) => i);
  for (let i = n - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

/**
 * Split a secret into `parts` shares, requiring `threshold` to reconstruct.
 *
 * Each share is secret.length + 1 bytes (the extra byte is the x-coordinate tag).
 * Parts and threshold must be in [2, 255], parts >= threshold, secret non-empty.
 */
export function split(secret: Buffer, parts: number, threshold: number): Buffer[] {
  if (parts < threshold) {
    throw new Error("shamir: parts cannot be less than threshold");
  }
  if (parts > 255) {
    throw new Error("shamir: parts cannot exceed 255");
  }
  if (threshold < 2) {
    throw new Error("shamir: threshold must be at least 2");
  }
  if (threshold > 255) {
    throw new Error("shamir: threshold cannot exceed 255");
  }
  if (secret.length === 0) {
    throw new Error("shamir: cannot split an empty secret");
  }

  // Random permutation for unique x-coordinates (1-indexed, never 0)
  const xCoordinates = randomPerm(255);

  // Allocate output shares: each is [y0, y1, ..., yN, x]
  const out: Buffer[] = [];
  for (let i = 0; i < parts; i++) {
    const share = Buffer.alloc(secret.length + SHARE_OVERHEAD);
    share[secret.length] = xCoordinates[i] + 1;
    out.push(share);
  }

  // For each byte of the secret, create a random polynomial with the byte as intercept
  for (let idx = 0; idx < secret.length; idx++) {
    const p = makePolynomial(secret[idx], threshold - 1);

    for (let i = 0; i < parts; i++) {
      const x = xCoordinates[i] + 1;
      out[i][idx] = evaluate(p, x);
    }
  }

  return out;
}

/**
 * Combine shares to reconstruct the original secret.
 *
 * Requires at least 2 shares (the threshold used during split).
 * All shares must be the same length.
 */
export function combine(parts: Buffer[]): Buffer {
  if (parts.length < 2) {
    throw new Error("shamir: less than two parts cannot be used to reconstruct the secret");
  }

  const firstPartLen = parts[0].length;
  if (firstPartLen < 2) {
    throw new Error("shamir: parts must be at least two bytes");
  }
  for (let i = 1; i < parts.length; i++) {
    if (parts[i].length !== firstPartLen) {
      throw new Error("shamir: all parts must be the same length");
    }
  }

  const secretLen = firstPartLen - SHARE_OVERHEAD;
  const secret = Buffer.alloc(secretLen);

  // Extract x-coordinates and check for duplicates
  const xSamples = new Uint8Array(parts.length);
  const ySamples = new Uint8Array(parts.length);
  const seen = new Set<number>();

  for (let i = 0; i < parts.length; i++) {
    const x = parts[i][secretLen];
    if (seen.has(x)) {
      throw new Error("shamir: duplicate part detected");
    }
    seen.add(x);
    xSamples[i] = x;
  }

  // Reconstruct each byte via Lagrange interpolation at x=0
  for (let idx = 0; idx < secretLen; idx++) {
    for (let i = 0; i < parts.length; i++) {
      ySamples[i] = parts[i][idx];
    }
    secret[idx] = interpolatePolynomial(xSamples, ySamples, 0);
  }

  return secret;
}
