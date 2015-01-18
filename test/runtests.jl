using Base.Test

include("../src/aes-modes.jl")

# Test cases from FIPS 197
@test gmul(0x57, 0x13) == 0xfe
@test gmul(0x00, 0x00) == 0x00
@test gmul(0x01, 0x01) == 0x01

# Test for property of gmul and gmulinv
for b=0x01:0xFF
	@test gmul(b, gmulinv(b)) == 0x01
end

# Test cases from FIPS 197
const keyunexp1 = [ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c ]
const keyexp1 = KeyExpansion(keyunexp1, Nks[1], Nrs[1])
const keyexp1expect = "2b7e151628aed2a6abf7158809cf4f3ca0fafe1788542cb123a339392a6c7605f2c295f27a96b9435935807a7359f67f3d80477d4716fe3e1e237e446d7a883bef44a541a8525b7fb671253bdb0bad00d4d1c6f87c839d87caf2b8bc11f915bc6d88a37a110b3efddbf98641ca0093fd4e54f70e5f5fc9f384a64fb24ea6dc4fead27321b58dbad2312bf5607f8d292fac7766f319fadc2128d12941575c006ed014f9a8c9ee2589e13f0cc8b6630ca6"

@test bytes2hex(keyexp1) == keyexp1expect

# Tests from OpenDocument spreadsheet available at
# http://www.nayuki.io/page/aes-cipher-internals-in-excel
const key128 =    "2b7e151628aed2a6abf7158809cf4f3c"
const plain128 =  "3243f6a8885a308d313198a2e0370734"
const cipher128 = "3925841d02dc09fbdc118597196a0b32"

@test AESEncrypt(plain128, key128) == cipher128

# Test vectors from
# http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors

# AES-128
const key1 =    "2b7e151628aed2a6abf7158809cf4f3c"
const plain1 =  "6bc1bee22e409f96e93d7e117393172a"
const cipher1 = "3ad77bb40d7a3660a89ecaf32466ef97"

# AES-192
const key2 =    "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
const plain2 =  "6bc1bee22e409f96e93d7e117393172a"
const cipher2 = "bd334f1d6e45f25ff712a214571fa5cc"

# AES-256
const key3 =    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
const plain3 =  "6bc1bee22e409f96e93d7e117393172a"
const cipher3 = "f3eed1bdb5d2a03c064b5a7e3db181f8"

# Encryption tests
@test AESEncrypt(plain1, key1) == cipher1
@test AESEncrypt(plain2, key2) == cipher2
@test AESEncrypt(plain3, key3) == cipher3

# Decryption tests
@test AESDecrypt(cipher1, key1) == plain1
@test AESDecrypt(cipher2, key2) == plain2
@test AESDecrypt(cipher3, key3) == plain3

# AES ECB
const key4 =    "2b7e151628aed2a6abf7158809cf4f3c"
const plain4 =  "6bc1bee22e409f96e93d7e117393172a"
const cipher4 = "3ad77bb40d7a3660a89ecaf32466ef97"

@test AESECB(plain4, key4, true) == cipher4
@test AESECB(cipher4, key4, false) == plain4

# AES CBC
const iv5 =     "000102030405060708090a0b0c0d0e0f"
const key5 =    key4
const plain5 =  plain4
const cipher5 = "7649abac8119b246cee98e9b12e9197d"

@test AESCBC(plain5, key5, iv5, true) == cipher5
@test AESCBC(cipher5, key5, iv5, false) == plain5

# AES CFB
const iv6 =     iv5
const key6 =    key4
const plain6 =  plain4
const cipher6 = "3b3fd92eb72dad20333449f8e83cfb4a"

@test AESCFB(plain6, key6, iv6, true) == cipher6
@test AESCFB(cipher6, key6, iv6, false) == plain6

# AES OFB
const iv7 =     iv5
const key7 =    key4
const plain7 =  plain4
const cipher7 = cipher6

@test AESOFB(plain7, key7, iv7) == cipher7
@test AESOFB(cipher7, key7, iv7) == plain7

# AES CTR
const iv8 =     "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff" # is actually the nonce
const key8 =    key4
const plain8 =  plain4
const cipher8 = "874d6191b620e3261bef6864990db6ce"

@test AESCTR(plain8, key8, iv8) == cipher8
@test AESCTR(cipher8, key8, iv8) == plain8

# Encrypt three random blocks using different modes of operation and
# check if decryption recovers original blocks
const BLOCK_BYTES = 16
const ivrand =     rand(Uint8, BLOCK_BYTES)
const keysrand =   rand(Uint8, div(128, 8))
const keymrand =   rand(Uint8, div(192, 8))
const keylrand =   rand(Uint8, div(256, 8))
const plainrand =  rand(Uint8, 3 * BLOCK_BYTES)
const plainrandl = rand(Uint8, 3 * BLOCK_BYTES + 1)

# AES ECB
for key in (keysrand, keymrand, keylrand)
	cipherrand = AESECB(plainrand, key, true)
	@test cipherrand != plainrand
	@test AESECB(cipherrand, key, false) == plainrand
end

# AES CBC
for key in (keysrand, keymrand, keylrand)
	cipherrand = AESCBC(plainrand, key, ivrand, true)
	@test cipherrand != plainrand
	@test AESCBC(cipherrand, key, ivrand, false) == plainrand
end

# AES CFB
for key in (keysrand, keymrand, keylrand)
	for plain in (plainrand, plainrandl)
		cipherrand = AESCFB(plain, key, ivrand, true)
		@test cipherrand != plain
		@test AESCFB(cipherrand, key, ivrand, false) == plain
	end
end

# AES OFB
for key in (keysrand, keymrand, keylrand)
	for plain in (plainrand, plainrandl)
		cipherrand = AESOFB(plain, key, ivrand)
		@test cipherrand != plain
		@test AESOFB(cipherrand, key, ivrand) == plain
	end
end

# AES CTR
for key in (keysrand, keymrand, keylrand)
	for plain in (plainrand, plainrandl)
		cipherrand = AESCTR(plain, key, ivrand)
		@test cipherrand != plain
		@test AESCTR(cipherrand, key, ivrand) == plain
	end
end

