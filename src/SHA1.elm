module SHA1 exposing
    ( Digest
    , fromString
    , toHex, toBase64
    , fromBytes, toBytes
    , fromByte
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
import Base64
import Bitwise exposing (and, complement, or, shiftLeftBy, shiftRightZfBy)
import Bytes exposing (Bytes, Endianness(..))
import Bytes.Decode as Decode exposing (Decoder, Step(..))
import Bytes.Encode as Encode
import Hex



-- CONSTANTS


blockSize : Int
blockSize =
    64


numberOfWords : Int
numberOfWords =
    16



-- TYPES


type Tuple5
    = Tuple5 Int Int Int Int Int


{-| A type to represent a message digest. `SHA1.Digest`s are equatable, and you may
want to consider keeping any digests you need in your `Model` as `Digest`s, not
as `String`s created by [`toHex`](#toHex) or [`toBase64`](#toBase64).
-}
type Digest
    = Digest Tuple5


type State
    = State Tuple5


type DeltaState
    = DeltaState Tuple5



-- CALCULATING


{-| Create a digest from a `String`.

    "hello world" |> SHA1.fromString |> SHA1.toHex
    --> "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"

-}
fromString : String -> Digest
fromString =
    hashBytesValue << Encode.encode << Encode.string


{-| Sometimes you have binary data that's not representable in a string. Create
a digest from the raw "bytes", i.e. a `List` of `Int`s. Any items not between 0
and 255 are discarded.

    SHA1.fromBytes [72, 105, 33, 32, 240, 159, 152, 132]
    --> SHA1.fromString "Hi! 😄"

    [0x00, 0xFF, 0x34, 0xA5] |> SHA1.fromBytes |> SHA1.toBase64
    --> "sVQuFckyE6K3fsdLmLHmq8+J738="

-}
fromBytes : List Int -> Digest
fromBytes input =
    input
        |> List.map Encode.unsignedInt8
        |> Encode.sequence
        |> Encode.encode
        |> hashBytesValue


fromByte : Bytes -> Digest
fromByte =
    hashBytesValue


hashBytesValue : Bytes -> Digest
hashBytesValue bytes =
    let
        byteCount =
            Bytes.width bytes

        -- The full message (message + 1 byte for message end flag (0x80) + 8 bytes for message length)
        -- has to be a multiple of 64 bytes (i.e. of 512 bits).
        -- The 4 is because the bitCountInBytes is supposed to be 8 long, but it's only 4 (8 - 4 = 4)
        zeroBytesToAppend =
            4 + modBy 64 (56 - modBy 64 (byteCount + 1))

        message =
            Encode.encode
                (Encode.sequence
                    [ Encode.bytes bytes
                    , Encode.unsignedInt8 0x80
                    , Encode.sequence (List.repeat zeroBytesToAppend (Encode.unsignedInt8 0))

                    -- The 3s are to convert byte count to bit count (2^3 = 8)
                    , byteCount |> shiftRightZfBy (0x18 - 3) |> and 0xFF |> Encode.unsignedInt8
                    , byteCount |> shiftRightZfBy (0x10 - 3) |> and 0xFF |> Encode.unsignedInt8
                    , byteCount |> shiftRightZfBy (0x08 - 3) |> and 0xFF |> Encode.unsignedInt8
                    , byteCount |> shiftLeftBy 3 |> and 0xFF |> Encode.unsignedInt8
                    ]
                )

        numberOfChunks =
            Bytes.width message // 64

        hashState =
            iterate numberOfChunks reduceBytesMessage initialState
    in
    case Decode.decode hashState message of
        Just (State digest) ->
            Digest digest

        Nothing ->
            -- impossible case
            case initialState of
                State digest ->
                    Digest digest


i32 : Decoder Int
i32 =
    Decode.unsignedInt32 BE


reduceBytesMessage : State -> Decoder State
reduceBytesMessage state =
    map16 (reduceMessage_ state) i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32


reduceMessage_ (State (Tuple5 h0 h1 h2 h3 h4)) b16 b15 b14 b13 b12 b11 b10 b9 b8 b7 b6 b5 b4 b3 b2 b1 =
    let
        initialDeltaState =
            DeltaState (Tuple5 h0 h1 h2 h3 h4)
                |> calculateDigestDeltas 0 b1
                |> calculateDigestDeltas 1 b2
                |> calculateDigestDeltas 2 b3
                |> calculateDigestDeltas 3 b4
                |> calculateDigestDeltas 4 b5
                |> calculateDigestDeltas 5 b6
                |> calculateDigestDeltas 6 b7
                |> calculateDigestDeltas 7 b8
                |> calculateDigestDeltas 8 b9
                |> calculateDigestDeltas 9 b10
                |> calculateDigestDeltas 10 b11
                |> calculateDigestDeltas 11 b12
                |> calculateDigestDeltas 12 b13
                |> calculateDigestDeltas 13 b14
                |> calculateDigestDeltas 14 b15
                |> calculateDigestDeltas 15 b16

        (DeltaState (Tuple5 a b c d e)) =
            reduceWordsHelp 0 initialDeltaState b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14 b15 b16
    in
    State (Tuple5 (trim (h0 + a)) (trim (h1 + b)) (trim (h2 + c)) (trim (h3 + d)) (trim (h4 + e)))


{-| Fold over the words, keeping track of the deltas.

We must keep track of the 16 most recent values, and use plain arguments for efficiency reasons.
So in the recursion, `b16` is dropped, all the others shift one position to the left, and `value` is the final argument.
Then the `deltaState` is also updated with the `value`.

-}
reduceWordsHelp i deltaState b16 b15 b14 b13 b12 b11 b10 b9 b8 b7 b6 b5 b4 b3 b2 b1 =
    if (i - blockSize) < 0 then
        let
            value =
                b3
                    |> Bitwise.xor b8
                    |> Bitwise.xor b14
                    |> Bitwise.xor b16
                    |> rotateLeftBy 1
        in
        reduceWordsHelp (i + 1) (calculateDigestDeltas (i + numberOfWords) value deltaState) b15 b14 b13 b12 b11 b10 b9 b8 b7 b6 b5 b4 b3 b2 b1 value

    else
        deltaState


calculateDigestDeltas : Int -> Int -> DeltaState -> DeltaState
calculateDigestDeltas index int (DeltaState (Tuple5 a b c d e)) =
    let
        -- benchmarks show integer division and cases on the integter are the fastest
        f =
            case index // 20 of
                0 ->
                    or (and b c) (and (Bitwise.and 0xFFFFFFFF (complement b)) d) + 0x5A827999

                1 ->
                    Bitwise.xor b (Bitwise.xor c d) + 0x6ED9EBA1

                2 ->
                    or (or (and b c) (and b d)) (and c d) + 0x8F1BBCDC

                _ ->
                    Bitwise.xor b (Bitwise.xor c d) + 0xCA62C1D6

        newA =
            (Bitwise.or (Bitwise.shiftRightZfBy 27 a) (Bitwise.shiftLeftBy 5 a) + f + e + int)
                |> Bitwise.shiftRightZfBy 0
    in
    DeltaState (Tuple5 newA a (rotateLeftBy 30 b) c d)


trim : Int -> Int
trim =
    Bitwise.and 0xFFFFFFFF


rotateLeftBy : Int -> Int -> Int
rotateLeftBy amount i =
    Bitwise.or (Bitwise.shiftRightZfBy (32 - amount) i) (Bitwise.shiftLeftBy amount i)
        |> Bitwise.shiftRightZfBy 0


initialState : State
initialState =
    State (Tuple5 0x67452301 0xEFCDAB89 0x98BADCFE 0x10325476 0xC3D2E1F0)



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
toBytes (Digest (Tuple5 a b c d e)) =
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
toHex (Digest (Tuple5 a b c d e)) =
    wordToHex a ++ wordToHex b ++ wordToHex c ++ wordToHex d ++ wordToHex e


wordToHex : Int -> String
wordToHex int =
    let
        left =
            int
                |> shiftRightZfBy 0x10
                |> Hex.toString
                |> String.padLeft 4 '0'

        right =
            int
                |> and 0xFFFF
                |> Hex.toString
                |> String.padLeft 4 '0'
    in
    left ++ right



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
toBase64 (Digest (Tuple5 a b c d e)) =
    let
        buffer =
            [ Encode.unsignedInt32 BE a
            , Encode.unsignedInt32 BE b
            , Encode.unsignedInt32 BE c
            , Encode.unsignedInt32 BE d
            , Encode.unsignedInt32 BE e
            ]
    in
    buffer
        |> Encode.sequence
        |> Encode.encode
        |> Base64.fromBytes
        |> Maybe.withDefault ""



-- HELPERS


{-| The most efficient implmenentation for `map16`, given that `Decode.map5` is the highest defined in Kernel code
-}
map16 :
    (b1 -> b2 -> b3 -> b4 -> b5 -> b6 -> b7 -> b8 -> b9 -> b10 -> b11 -> b12 -> b13 -> b14 -> b15 -> b16 -> result)
    -> Decoder b1
    -> Decoder b2
    -> Decoder b3
    -> Decoder b4
    -> Decoder b5
    -> Decoder b6
    -> Decoder b7
    -> Decoder b8
    -> Decoder b9
    -> Decoder b10
    -> Decoder b11
    -> Decoder b12
    -> Decoder b13
    -> Decoder b14
    -> Decoder b15
    -> Decoder b16
    -> Decoder result
map16 f b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14 b15 b16 =
    Decode.succeed f
        |> Decode.map5 (\a b c d e -> e d c b a) b4 b3 b2 b1
        |> Decode.map5 (\a b c d e -> e d c b a) b8 b7 b6 b5
        |> Decode.map5 (\a b c d e -> e d c b a) b12 b11 b10 b9
        |> Decode.map5 (\a b c d e -> e d c b a) b16 b15 b14 b13


{-| Iterate a decoder `n` times

Needs some care to not run into stack overflow. This definition is nicely tail-recursive.

-}
iterate : Int -> (a -> Decoder a) -> a -> Decoder a
iterate n step initial =
    iterateHelp n (\value -> Decode.andThen step value) (Decode.succeed initial)


iterateHelp n step initial =
    if n > 0 then
        iterateHelp (n - 1) step (step initial)

    else
        initial
