.global gBuiltinSignatureFile

gBuiltinSignatureFile:
    .incbin "builtin_signatures.sig"
    .long 0
