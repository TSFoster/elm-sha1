module SHA1 exposing
    ( Digest
    , fromString
    , toHex, toBase64
    , fromBytes, toBytes
    )

{-| [SHA-1] is a [cryptographic hash function].
Although it is no longer considered cryptographically secure (as collisions can
be found faster than brute force), it is still very suitable for a broad range
of uses, and is a lot stronger than MD5.

[SHA-1]: https://en.wikipedia.org/wiki/SHA-1
[cryptographic hash function]: https://en.wikipedia.org/wiki/Cryptographic_hash_function

This package provides a way of creating SHA-1 digests from `String`s and `List
Int`s (where each `Int` is between 0 and 255, and represents a byte). It can
also take those `Digest`s and format them in [hexadecimal] or [base64] notation.
Alternatively, you can get the binary digest, using a `List  Int` to represent
the bytes.

[hexadecimal]: https://en.wikipedia.org/wiki/Hexadecimal
[base64]: https://en.wikipedia.org/wiki/Base64

**Note:** Currently, the package can only create digests for around 200kb of
data. If there is any interest in using this package for hashing >200kb, or for
hashing [elm/bytes], [let me know][issues]!

[elm/bytes]: https://github.com/elm/bytes
[issues]: https://github.com/TSFoster/elm-sha1/issues

@docs Digest


# Creating digests

@docs fromString


# Formatting digests

@docs toHex, toBase64


# Binary data

@docs fromBytes, toBytes

-}

import Array exposing (Array)
import Bitwise exposing (and, complement, or, shiftLeftBy, shiftRightZfBy, xor)
import Hex
import List.Extra exposing (groupsOf, indexedFoldl)
import String.UTF8 as UTF8



-- TYPES


{-| A type to represent a message digest. `SHA1.Digest`s are equatable, and you may
want to consider keeping any digests you need in your `Model` as `Digest`s, not
as `String`s created by [`toHex`](#toHex) or [`toBase64`](#toBase64).
-}
type Digest
    = Digest Int Int Int Int Int


type alias State =
    { h0 : Int
    , h1 : Int
    , h2 : Int
    , h3 : Int
    , h4 : Int
    }


type alias DeltaState =
    { a : Int
    , b : Int
    , c : Int
    , d : Int
    , e : Int
    }



-- CALCULATING


{-| Create a digest from a `String`.

    "hello world" |> SHA1.fromString |> SHA1.toHex
    --> "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"

-}
fromString : String -> Digest
fromString =
    UTF8.toBytes >> hashBytes


{-| Sometimes you have binary data that's not representable in a string. Create
a digest from the raw "bytes", i.e. a `List` of `Int`s. Any items not between 0
and 255 are discarded.

    SHA1.fromBytes [72, 105, 33, 32, 240, 159, 152, 132]
    --> SHA1.fromString "Hi! 😄"

    [0x00, 0xFF, 0x34, 0xA5] |> SHA1.fromBytes |> SHA1.toBase64
    --> "sVQuFckyE6K3fsdLmLHmq8+J738="

-}
fromBytes : List Int -> Digest
fromBytes =
    List.filter (\i -> i >= 0 && i <= 255) >> hashBytes


hashBytes : List Int -> Digest
hashBytes bytes =
    let
        byteCount =
            List.length bytes

        -- The 3s are to convert byte count to bit count (2^3 = 8)
        bitCountInBytes =
            [ byteCount |> shiftRightZfBy (0x18 - 3) |> and 0xFF
            , byteCount |> shiftRightZfBy (0x10 - 3) |> and 0xFF
            , byteCount |> shiftRightZfBy (0x08 - 3) |> and 0xFF
            , byteCount |> shiftLeftBy 3 |> and 0xFF
            ]

        -- The full message (message + 1 byte for message end flag (0x80) + 8 bytes for message length)
        -- has to be a multiple of 64 bytes (i.e. of 512 bits).
        -- The 4 is because the bitCountInBytes is supposed to be 8 long, but it's only 4 (8 - 4 = 4)
        zeroBytesToAppend =
            4 + modBy 64 (56 - modBy 64 (byteCount + 1))

        bytesToAppend =
            0x80 :: List.repeat zeroBytesToAppend 0x00 ++ bitCountInBytes

        message =
            bytes ++ bytesToAppend

        chunks =
            groupsOf 64 message

        hashState =
            List.foldl reduceMessage init chunks
    in
    finalDigest hashState


finalDigest : State -> Digest
finalDigest { h0, h1, h2, h3, h4 } =
    Digest h0 h1 h2 h3 h4


reduceMessage : List Int -> State -> State
reduceMessage chunk { h0, h1, h2, h3, h4 } =
    let
        words =
            chunk
                |> groupsOf 4
                |> List.map wordFromInts
                |> Array.fromList

        initialDeltas =
            DeltaState h0 h1 h2 h3 h4

        { a, b, c, d, e } =
            List.Extra.initialize 64 ((+) 16)
                |> List.foldl reduceWords words
                |> Array.toList
                |> indexedFoldl calculateDigestDeltas initialDeltas
    in
    State (trim (h0 + a)) (trim (h1 + b)) (trim (h2 + c)) (trim (h3 + d)) (trim (h4 + e))


calculateDigestDeltas : Int -> Int -> DeltaState -> DeltaState
calculateDigestDeltas index int { a, b, c, d, e } =
    let
        ( f, k ) =
            if index < 20 then
                ( or (and b c) (and (trim (complement b)) d)
                , 0x5A827999
                )

            else if index < 40 then
                ( xor b (xor c d)
                , 0x6ED9EBA1
                )

            else if index < 60 then
                ( or (or (and b c) (and b d)) (and c d)
                , 0x8F1BBCDC
                )

            else
                ( xor b (xor c d)
                , 0xCA62C1D6
                )
    in
    { a = trim (trim (trim (trim (rotateLeftBy 5 a + f) + e) + k) + int)
    , b = a
    , c = rotateLeftBy 30 b
    , d = c
    , e = d
    }


trim : Int -> Int
trim =
    and 0xFFFFFFFF


reduceWords : Int -> Array Int -> Array Int
reduceWords index words =
    let
        v i =
            Array.get (index - i) words

        val =
            [ v 3, v 8, v 14, v 16 ]
                |> List.filterMap identity
                |> List.foldl xor 0
                |> rotateLeftBy 1
    in
    Array.push val words


rotateLeftBy : Int -> Int -> Int
rotateLeftBy amount i =
    trim <| shiftRightZfBy (32 - amount) i + trim (shiftLeftBy amount i)


wordFromInts : List Int -> Int
wordFromInts ints =
    case ints of
        a :: b :: c :: d :: [] ->
            List.foldl or
                d
                [ shiftLeftBy 0x08 c
                , shiftLeftBy 0x10 b
                , shiftLeftBy 0x18 a
                ]

        _ ->
            0


init : State
init =
    State 0x67452301 0xEFCDAB89 0x98BADCFE 0x10325476 0xC3D2E1F0



-- FORMATTING


{-| If you need the raw digest instead of the textual representation (for
example, if using SHA-1 as part of another algorithm), `toBytes` is what you're
looking for!

    "And the band begins to play"
        |> SHA1.fromString
        |> SHA1.toBytes
    --> [ 0xF3, 0x08, 0x73, 0x13
    --> , 0xD6, 0xBC, 0xE5, 0x5B
    --> , 0x60, 0x0C, 0x69, 0x2F
    --> , 0xE0, 0x92, 0xF4, 0x53
    --> , 0x87, 0x3F, 0xAE, 0x91
    --> ]

-}
toBytes : Digest -> List Int
toBytes (Digest a b c d e) =
    List.concatMap wordToBytes [ a, b, c, d, e ]


wordToBytes : Int -> List Int
wordToBytes int =
    [ int |> shiftRightZfBy 0x18 |> and 0xFF
    , int |> shiftRightZfBy 0x10 |> and 0xFF
    , int |> shiftRightZfBy 0x08 |> and 0xFF
    , int |> and 0xFF
    ]


{-| One of the two canonical ways of representing a SHA-1 digest is with 40
hexadecimal digits.

    "And our friends are all aboard"
        |> SHA1.fromString
        |> SHA1.toHex
    --> "f9a0c23ddcd40f6956b0cf59cd9b8800d71de73d"

-}
toHex : Digest -> String
toHex (Digest a b c d e) =
    [ a, b, c, d, e ]
        |> List.map wordToHex
        |> String.concat


wordToHex : Int -> String
wordToHex int =
    let
        left =
            int |> shiftRightZfBy 0x10

        right =
            int |> and 0xFFFF
    in
    [ left, right ]
        |> List.map (Hex.toString >> String.padLeft 4 '0')
        |> String.concat



-- Base64 uses 1 character per 6 bits, which doesn't divide very nicely into our
-- 5 32-bit  integers! The  base64 digest  is 28  characters long,  although the
-- final character  is a '=',  which means it's  padded. Therefore, it  uses 162
-- bits  of entropy  to display  our 160  bit  digest, so  the digest  has 2  0s
-- appended.


{-| One of the two canonical ways of representing a SHA-1 digest is in a 20
digit long Base64 binary to ASCII text encoding.

    "Many more of them live next door"
        |> SHA1.fromString
        |> SHA1.toBase64
    --> "jfL0oVb5xakab6BMLplGe2XPbj8="

-}
toBase64 : Digest -> String
toBase64 (Digest a b c d e) =
    [ a |> shiftRightZfBy 8
    , (a |> and 0xFF |> shiftLeftBy 16) + (b |> shiftRightZfBy 16)
    , (b |> and 0xFFFF |> shiftLeftBy 8) + (c |> shiftRightZfBy 24)
    , c |> and 0x00FFFFFF
    , d |> shiftRightZfBy 8
    , (d |> and 0xFF |> shiftLeftBy 16) + (e |> shiftRightZfBy 16)
    , e |> and 0xFFFF |> shiftLeftBy 8
    ]
        |> List.map intToBase64
        |> String.concat
        |> String.dropRight 1
        |> (\s -> s ++ "=")



-- Converts the least-significant 24 bits to 4 base64 chars


intToBase64 : Int -> String
intToBase64 int =
    [ int |> shiftRightZfBy 18 |> and 0x3F
    , int |> shiftRightZfBy 12 |> and 0x3F
    , int |> shiftRightZfBy 6 |> and 0x3F
    , int |> and 0x3F
    ]
        |> List.map Array.get
        |> List.filterMap ((|>) base64Chars)
        |> String.fromList


base64Chars : Array Char
base64Chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        |> String.toList
        |> Array.fromList
