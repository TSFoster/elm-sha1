# SHA1

Calculate SHA-1 digests in Elm.

This package can take a message as a `String` or `List Int` ("bytes") calculate SHA-1 digests, and represent them in [hexadecimal], [base64] or a `List Int` (as "bytes").

[hexadecimal]: https://en.wikipedia.org/wiki/Hexadecimal
[base64]: https://en.wikipedia.org/wiki/Base64

# [Documentation](https://package.elm-lang.org/packages/TSFoster/elm-sha1/latest/SHA1)

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

SHA1.toBytes digest2
    |> List.length
--> 20
```
