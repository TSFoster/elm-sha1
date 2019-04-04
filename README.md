# SHA1

Calculate SHA-1 digests in Elm.

This package can take a message as a `String` or `List Int` ("bytes") calculate
SHA-1 digests, and represent them in [hexadecimal], [base64] or a `List Int` (as
"bytes").

[hexadecimal]: https://en.wikipedia.org/wiki/Hexadecimal
[base64]: https://en.wikipedia.org/wiki/Base64

# [Documentation](https://package.elm-lang.org/packages/TSFoster/elm-sha1/latest/SHA1)

## IMPORTANT: Incorrect calculation in older versions

Please note that [there was an issue][issue-2] regarding input data of 311 bytes
in versions 1.0.0 and 1.0.1 of this library. If you are using either of these
versions, it is highly recommended that you upgrade as soon as possible.

[issue-2]: https://github.com/TSFoster/elm-sha1/issues/2

## Examples

```elm
import SHA1

digest1 : SHA1.Digest
digest1 = SHA1.fromString "string"

digest2 : SHA1.Digest
digest2 = SHA1.fromBytes [0x00, 0xFF, 0xCE, 0x35, 0x74]


SHA1.toHex digest1
--> "ecb252044b5ea0f679ee78ec1a12904739e2904d"

SHA1.toBase64 digest2
--> "gHweOF5Lyg+Ha7ujrlYwNa/Hwgk="

SHA1.toBytes digest1
--> [ 0xEC, 0xB2, 0x52, 0x04, 0x4B
--> , 0x5E, 0xA0, 0xF6, 0x79, 0xEE
--> , 0x78, 0xEC, 0x1A, 0x12, 0x90
--> , 0x47, 0x39, 0xE2, 0x90, 0x4D
--> ]
```

## Validation

Not officially validated through [CAVP](http://csrc.nist.gov/groups/STM/cavp/)/[CMVP](https://csrc.nist.gov/groups/STM/cmvp/).

Tested against hashes in [tests/Tests.elm](https://github.com/TSFoster/elm-sha1/blob/master/tests/Tests.elm), indirectly in [romariolopezc/elm-hmac-sha1’s tests](https://github.com/romariolopezc/elm-hmac-sha1/blob/master/tests/HmacSha1Test.elm), and personal use of and the [tests](https://github.com/TSFoster/elm-uuid/blob/2.2.0/tests/Tests.elm) for [TSFoster/elm-uuid](https://package.elm-lang.org/packages/TSFoster/elm-uuid/latest/).

Please note that SHA-1 is not “[considered secure against well-funded opponents](https://en.wikipedia.org/wiki/SHA-1)”, but it does have its uses, including, but not limited to, [version 5 UUIDs](https://package.elm-lang.org/packages/TSFoster/elm-uuid/latest/UUID#childNamed).
