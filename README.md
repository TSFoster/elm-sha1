# SHA1

Calculate SHA-1 digests in Elm.

This package supports hashing of:

* `String` using the utf-8 encoding
* `List Int` where the elements are assumed to be below 256
* `Bytes` an `elm/bytes` sequence of byte values

And can represent the digest as 

* a [hexadecimal] string
* a [base64] string
* a `List Int` of byte values
* a `Bytes` 

[hexadecimal]: https://en.wikipedia.org/wiki/Hexadecimal
[base64]: https://en.wikipedia.org/wiki/Base64

# [Documentation](https://package.elm-lang.org/packages/TSFoster/elm-sha1/latest/SHA1)

## IMPORTANT UPGRADE NOTES

- **Upgrade to elm-sha1 >= v1.0.3 for use with elm v0.19.1.** An update to the
  elm compiler to fix a [regression][issue-1945] will break versions of this
  package before v1.0.3. Please ensure this package is updated to at least v1.0.3
  when upgrading to elm version 0.19.1.

- [There was an issue][issue-2] regarding input data of 311 bytes in versions
  1.0.0 and 1.0.1 of this library. If you are using either of these versions, it
  is highly recommended that you upgrade as soon as possible.

[issue-2]: https://github.com/TSFoster/elm-sha1/issues/2
[issue-1945]: https://github.com/elm/compiler/issues/1945

## Examples

```elm
import Bytes.Encode as Encode
import Bytes exposing (Bytes)
import SHA1

digest1 : SHA1.Digest
digest1 = SHA1.fromString "string"

byteValues : List Int 
byteValues = [0x00, 0xFF, 0xCE, 0x35, 0x74]

digest2 : SHA1.Digest
digest2 = SHA1.fromByteValues byteValues

buffer : Bytes
buffer = 
    List.map Encode.unsignedInt8 byteValues
        |> Encode.sequence
        |> Encode.encode 

digest3 : SHA1.Digest 
digest3 = SHA1.fromBytes buffer

SHA1.toHex digest1
--> "ecb252044b5ea0f679ee78ec1a12904739e2904d"

SHA1.toBase64 digest2
--> "gHweOF5Lyg+Ha7ujrlYwNa/Hwgk="

SHA1.toByteValues digest3
--> [ 0x80, 0x7C, 0x1E, 0x38
--> , 0x5E, 0x4B, 0xCA, 0x0F
--> , 0x87, 0x6B, 0xBB, 0xA3
--> , 0xAE, 0x56, 0x30, 0x35
--> , 0xAF, 0xC7, 0xC2, 0x09
--> ]
```

## Validation

Not officially validated through [CAVP](http://csrc.nist.gov/groups/STM/cavp/)/[CMVP](https://csrc.nist.gov/groups/STM/cmvp/), although digests are tested against CAVS responses via [pyca/cryptography](https://github.com/pyca/cryptography/tree/master/vectors/cryptography_vectors/hashes/SHA1).

This package is also tested against additional hashes in the documentation (using [elm-verify-examples](https://github.com/stoeffel/elm-verify-examples)), [tests/Tests.elm](https://github.com/TSFoster/elm-sha1/blob/master/tests/Tests.elm), and indirectly via [romariolopezc/elm-hmac-sha1’s tests](https://github.com/romariolopezc/elm-hmac-sha1/blob/master/tests/HmacSha1Test.elm), and [TSFoster/elm-uuid’s tests](https://github.com/TSFoster/elm-uuid/blob/2.2.0/tests/Tests.elm).

Please note that SHA-1 is not “[considered secure against well-funded opponents](https://en.wikipedia.org/wiki/SHA-1)”, but it does have its uses, including, but not limited to, [version 5 UUIDs](https://package.elm-lang.org/packages/TSFoster/elm-uuid/latest/UUID#childNamed).
