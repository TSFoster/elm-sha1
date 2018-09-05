module SHA1 exposing (Digest, hash, toString)

import Array exposing (Array)
import Bitwise exposing (and, complement, or, shiftLeftBy, shiftRightZfBy, xor)
import Hex
import List.Extra exposing (groupsOf, indexedFoldl)
import String.UTF8 as UTF8


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


toString : Digest -> String
toString (Digest a b c d e) =
    [ a, b, c, d, e ]
        |> List.map Hex.toString
        |> List.map (String.padLeft 8 '0')
        |> String.concat


hash : String -> Digest
hash string =
    let
        bytes =
            UTF8.toBytes string

        byteCount =
            List.length bytes

        byteCountInBytes =
            Hex.toString byteCount |> String.padLeft 16 '0' |> String.toList |> pairHexChars

        zeroesToAppend =
            64 - modBy 64 (byteCount + 1 + 8)

        bytesToAppend =
            0x80 :: List.repeat zeroesToAppend 0x00 ++ byteCountInBytes

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
        chunks =
            Array.fromList (groupsOf 4 chunk)
                |> Array.map (List.foldl chunkFromInts 0)

        initialDeltas =
            DeltaState h0 h1 h2 h3 h4

        { a, b, c, d, e } =
            List.Extra.initialize 64 ((+) 16)
                |> List.foldl reduceChunk chunks
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


reduceChunk : Int -> Array Int -> Array Int
reduceChunk index chunks =
    let
        v i =
            Array.get (index - i) chunks

        val =
            [ v 3, v 8, v 14, v 16 ]
                |> List.filterMap identity
                |> List.foldl xor 0
                |> rotateLeftBy 1
    in
    Array.push val chunks


rotateLeftBy : Int -> Int -> Int
rotateLeftBy amount i =
    trim
        (shiftRightZfBy (32 - amount) (trim i)
            + trim (shiftLeftBy amount i)
        )


chunkFromInts : Int -> Int -> Int
chunkFromInts int acc =
    acc * 0x0100 + int


init : State
init =
    State 0x67452301 0xEFCDAB89 0x98BADCFE 0x10325476 0xC3D2E1F0


pairHexChars : List Char -> List Int
pairHexChars =
    groupsOf 2
        >> List.map String.fromList
        >> List.map Hex.fromString
        >> List.map (Result.withDefault 0)
