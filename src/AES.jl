module AES
	using LegacyStrings
	const ASCIIString = LegacyStrings.ASCIIString
	include("aes-modes.jl")
	export AESEncrypt, AESDecrypt, AESParameters
	export AESECB, AESCBC, AESCFB, AESOFB, AESCTR
end
