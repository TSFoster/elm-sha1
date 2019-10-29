# SHA1

Calculate SHA-1 digests in Elm.

This package supports hashing of:

* `String` using the utf-8 encoding
* `List Int` where the elements are assumed to be below 256

And can represent the digest as:

* a [hexadecimal] string
* a [base64] string
* a `List Int` of byte values

[hexadecimal]: https://en.wikipedia.org/wiki/Hexadecimal
[base64]: https://en.wikipedia.org/wiki/Base64

# [Documentation](https://package.elm-lang.org/packages/TSFoster/elm-sha1/latest/SHA1)

## IMPORTANT UPGRADE NOTES

- elm-sha1 >= v1.0.5 provides large performance improvements, thanks to [Folkert de Vries].

- **Upgrade to elm-sha1 >= v1.0.3 for use with elm v0.19.1.** An update to the
  elm compiler to fix a [regression][issue-1945] will break versions of this
  package before v1.0.3. Please ensure this package is updated to at least v1.0.3
  when upgrading to elm version 0.19.1.

- [There was an issue][issue-2] regarding input data of 311 bytes in versions
  1.0.0 and 1.0.1 of this library. If you are using either of these versions, it
  is highly recommended that you upgrade as soon as possible.

[Folkert de Vries]: https://github.com/folkertdev
[issue-2]: https://github.com/TSFoster/elm-sha1/issues/2
[issue-1945]: https://github.com/elm/compiler/issues/1945

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

Not officially validated through [CAVP]/[CMVP].

This package is also tested against additional hashes in the documentation (using [elm-verify-examples]), [tests/Tests.elm], and indirectly via [romariolopezc/elm-hmac-sha1’s tests][hmac-tests], and [TSFoster/elm-uuid’s tests][uuid-tests].

Please note that SHA-1 is not “[considered secure against well-funded opponents][sha1-wiki]”, but it does have its uses, including, but not limited to, [version 5 UUIDs][uuid-use].

[CAVP]: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
[CMVP]: https://csrc.nist.gov/projects/cryptographic-module-validation-program
[pyca/cryptography]: https://github.com/pyca/cryptography/tree/master/vectors/cryptography_vectors/hashes/SHA1

[elm-verify-examples]: https://github.com/stoeffel/elm-verify-examples
[tests/Tests.elm]: https://github.com/TSFoster/elm-sha1/blob/master/tests/Tests.elm
[hmac-tests]: https://github.com/romariolopezc/elm-hmac-sha1/blob/master/tests/HmacSha1Test.elm
[uuid-tests]: https://github.com/TSFoster/elm-uuid/blob/2.2.0/tests/Tests.elm

[sha1-wiki]: https://en.wikipedia.org/wiki/SHA-1
[uuid-use]: https://package.elm-lang.org/packages/TSFoster/elm-uuid/latest/UUID#childNamed


## Contributors

Special thanks to [Folkert de Vries](https://github.com/folkertdev) for a major rewrite of this library, including huge performance gains, more rigorous testing, and support for [elm/bytes].

Other contributors:

* [Colin T.A. Gray](https://github.com/colinta)
* [Dimitri Benin](https://github.com/BendingBender)


[elm/bytes]: https://package.elm-lang.org/packages/elm/bytes/latest/

## TODO

* Benchmarks
  * Add way to run benchmarks
  * Automate testing that changes do not negatively impact performance?
* Write CONTRIBUTING.md
