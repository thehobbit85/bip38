var aes = require('browserify-aes')
var assert = require('assert')
var bs58check = require('bs58check')
var createHash = require('create-hash')
var scrypt = require('scryptsy')
var xor = require('buffer-xor')

var ecurve = require('ecurve')
var curve = ecurve.getCurveByName('secp256k1')

var BigInteger = require('bigi')

// specified by BIP38
var scryptParams = {
  N: 16384,
  r: 8,
  p: 8
}

var NULL = new Buffer(0)

// SHA256(SHA256(buffer))
function sha256x2 (buffer) {
  buffer = createHash('sha256').update(buffer).digest()
  return createHash('sha256').update(buffer).digest()
}

function encryptRaw (buffer, compressed, passphrase, saltAddress) {
  if (buffer.length !== 32) throw new Error('Invalid private key length')

  var secret = new Buffer(passphrase, 'utf8')
  var salt = sha256x2(saltAddress).slice(0, 4)

  var N = scryptParams.N
  var r = scryptParams.r
  var p = scryptParams.p

  var scryptBuf = scrypt(secret, salt, N, r, p, 64)
  var derivedHalf1 = scryptBuf.slice(0, 32)
  var derivedHalf2 = scryptBuf.slice(32, 64)

  var xorBuf = xor(buffer, derivedHalf1)
  var cipher = aes.createCipheriv('aes-256-ecb', derivedHalf2, NULL)
  cipher.setAutoPadding(false)
  cipher.end(xorBuf)

  var cipherText = cipher.read()

  // 0x01 | 0x42 | flagByte | salt (4) | cipherText (32)
  var result = new Buffer(7 + 32)
  result[0] = 0x01
  result[1] = 0x42
  result[2] = compressed ? 0xe0 : 0xc0
  salt.copy(result, 3)
  cipherText.copy(result, 7)

  return result
}

function encrypt (buffer, compressed, passphrase, saltAddress) {
  return bs58check.encode(encryptRaw(buffer, compressed, passphrase, saltAddress))
}

// some of the techniques borrowed from: https://github.com/pointbiz/bitaddress.org
// todo: (optimization) init buffer in advance, and use copy instead of concat
function decryptRaw (buffer, passphrase) {
  // 39 bytes: 2 bytes prefix, 37 bytes payload
  if (buffer.length !== 39) throw new Error('Invalid BIP38 data length')
  if (buffer[0] !== 0x01) throw new Error('Invalid BIP38 prefix')

  // check if BIP38 EC multiply
  var type = buffer[1]
  if (type === 0x43) return decryptECMult(buffer, passphrase)
  if (type !== 0x42) throw new Error('Invalid BIP38 type')

  passphrase = new Buffer(passphrase, 'utf8')

  var flagByte = buffer[2]
  var compressed = flagByte === 0xe0
  if (!compressed && flagByte !== 0xc0) throw new Error('Invalid BIP38 compression flag')

  var N = scryptParams.N
  var r = scryptParams.r
  var p = scryptParams.p

  var addresshash = buffer.slice(3, 7)
  var scryptBuf = scrypt(passphrase, addresshash, N, r, p, 64)
  var derivedHalf1 = scryptBuf.slice(0, 32)
  var derivedHalf2 = scryptBuf.slice(32, 64)

  var privKeyBuf = buffer.slice(7, 7 + 32)
  var decipher = aes.createDecipheriv('aes-256-ecb', derivedHalf2, NULL)
  decipher.setAutoPadding(false)
  decipher.end(privKeyBuf)

  var plainText = decipher.read()
  var d = xor(plainText, derivedHalf1)

  return {
    d: d,
    compressed: compressed
  }
}

function decrypt (string, passphrase) {
  return decryptRaw(bs58check.decode(string), passphrase)
}

function decryptECMult (buffer, passphrase) {
  passphrase = new Buffer(passphrase, 'utf8')
  buffer = buffer.slice(1) // FIXME: we can avoid this

  var compressed = (buffer[1] & 0x20) !== 0
  var hasLotSeq = (buffer[1] & 0x04) !== 0

  assert.equal((buffer[1] & 0x24), buffer[1], 'Invalid private key.')

  var addresshash = buffer.slice(2, 6)
  var ownerEntropy = buffer.slice(6, 14)
  var ownerSalt

  // 4 bytes ownerSalt if 4 bytes lot/sequence
  if (hasLotSeq) {
    ownerSalt = ownerEntropy.slice(0, 4)

  // else, 8 bytes ownerSalt
  } else {
    ownerSalt = ownerEntropy
  }

  var encryptedPart1 = buffer.slice(14, 22) // First 8 bytes
  var encryptedPart2 = buffer.slice(22, 38) // 16 bytes

  var N = scryptParams.N
  var r = scryptParams.r
  var p = scryptParams.p
  var preFactor = scrypt(passphrase, ownerSalt, N, r, p, 32)

  var passFactor
  if (hasLotSeq) {
    var hashTarget = Buffer.concat([preFactor, ownerEntropy])
    passFactor = sha256x2(hashTarget)

  } else {
    passFactor = preFactor
  }

  var passInt = BigInteger.fromBuffer(passFactor)
  var passPoint = curve.G.multiply(passInt).getEncoded(true)

  var seedBPass = scrypt(passPoint, Buffer.concat([addresshash, ownerEntropy]), 1024, 1, 1, 64)
  var derivedHalf1 = seedBPass.slice(0, 32)
  var derivedHalf2 = seedBPass.slice(32, 64)

  var decipher = aes.createDecipheriv('aes-256-ecb', derivedHalf2, new Buffer(0))
  decipher.setAutoPadding(false)
  decipher.end(encryptedPart2)

  var decryptedPart2 = decipher.read()
  var tmp = xor(decryptedPart2, derivedHalf1.slice(16, 32))
  var seedBPart2 = tmp.slice(8, 16)

  var decipher2 = aes.createDecipheriv('aes-256-ecb', derivedHalf2, new Buffer(0))
  decipher2.setAutoPadding(false)
  decipher2.write(encryptedPart1) // first 8 bytes
  decipher2.end(tmp.slice(0, 8)) // last 8 bytes

  var seedBPart1 = xor(decipher2.read(), derivedHalf1.slice(0, 16))
  var seedB = Buffer.concat([seedBPart1, seedBPart2], 24)
  var factorB = BigInteger.fromBuffer(sha256x2(seedB))

  // d = passFactor * factorB (mod n)
  var d = passInt.multiply(factorB).mod(curve.n)

  return {
    d: d.toBuffer(32),
    compressed: compressed
  }
}

function verify (string) {
  var decoded
  try {
    decoded = bs58check.decode(string)
  } catch (e) {
    return false
  }

  if (decoded.length !== 39) return false
  if (decoded[0] !== 0x01) return false

  var type = decoded[1]
  var flag = decoded[2]

  // encrypted WIF
  if (type === 0x42) {
    if (flag !== 0xc0 && flag !== 0xe0) return false

  // EC mult
  } else if (type === 0x43) {
    if ((flag & ~0x24)) return false

  } else {
    return false
  }

  return true
}

module.exports = {
  decrypt: decrypt,
  decryptECMult: decryptECMult,
  decryptRaw: decryptRaw,
  encrypt: encrypt,
  encryptRaw: encryptRaw,
  verify: verify
}
