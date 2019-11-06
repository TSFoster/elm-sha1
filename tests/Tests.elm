module Tests exposing (suite)

import Bitwise
import Bytes exposing (Bytes)
import Bytes.Encode as Encode exposing (Encoder)
import Expect exposing (Expectation)
import Fuzz exposing (Fuzzer)
import Generated.SHA1LongMsg as Long
import Generated.SHA1ShortMsg as Short
import Hex
import Random exposing (Generator)
import Result exposing (Result)
import SHA1
import String.UTF8
import Test exposing (..)


type Input
    = FromByteValues (List Int)
    | FromString String
    | FromBytes Bytes


type ExpectedOutput
    = HexDigest String
    | Base64Digest String
    | ByteValuesDigest (List Int)
    | BytesDigest Bytes


type alias Digest =
    { a : Int, b : Int, c : Int, d : Int, e : Int }


suite : Test
suite =
    describe "elm-sha1"
        [ describe "SHA-1"
            [ describe "CAVS test suite"
                [ describe "long" (List.indexedMap fromCAVS Long.tests)
                , describe "short" (List.indexedMap fromCAVS Short.tests)
                ]
            , describe "from byte values"
                [ test "0..255" <|
                    expectation [ FromByteValues (List.range 0 255) ]
                        [ HexDigest "4916d6bdb7f78e6803698cab32d1586ea457dfc8", Base64Digest "SRbWvbf3jmgDaYyrMtFYbqRX38g=" ]
                , test "200KB" <|
                    expectation [ FromByteValues (List.repeat 200000 184) ]
                        [ HexDigest "707d33fe36b8bf5d21568058370ad9b70c5d1bfc", Base64Digest "cH0z/ja4v10hVoBYNwrZtwxdG/w=" ]
                ]
            , describe "from Bytes"
                [ test "30MB" <|
                    expectation [ FromBytes thirtyMegabytes ]
                        [ HexDigest "a869e551c0dfeaf152a594f9051b99a65d46f16d", Base64Digest "qGnlUcDf6vFSpZT5BRuZpl1G8W0=" ]
                ]
            , fuzz inputFuzzer "fromString, fromByteValues and fromBytes all equal" (\inputs -> expectation inputs [] ())
            , describe "Wikipedia examples"
                [ test "… lazy dog" <|
                    expectation [ FromString "The quick brown fox jumps over the lazy dog" ]
                        [ HexDigest "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", Base64Digest "L9ThxnotKPzthJ7hu3bnORuT6xI=" ]
                , test "… lazy cog" <|
                    expectation [ FromString "The quick brown fox jumps over the lazy cog" ]
                        [ HexDigest "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3", Base64Digest "3p8sf9JeGzr60+haC9F9mxANtLM=" ]
                , test "empty string" <|
                    expectation [ FromString "" ]
                        [ HexDigest "da39a3ee5e6b4b0d3255bfef95601890afd80709", Base64Digest "2jmj7l5rSw0yVb/vlWAYkK/YBwk=" ]
                ]
            , describe "hashing unicode"
                [ test "thumbs up" <|
                    expectation [ FromString "👍" ]
                        [ HexDigest "78654ffdf2db3ef8dd605074250103f770177eb6", Base64Digest "eGVP/fLbPvjdYFB0JQED93AXfrY=" ]
                , test "flag with modifiers" <|
                    expectation [ FromString "🏴\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}" ]
                        [ HexDigest "55bcc651f90bf1c3d5e9fcac0b52500ec3229aa2", Base64Digest "VbzGUfkL8cPV6fysC1JQDsMimqI=" ]
                ]
            , describe "generated strings"
                [ test "random string 1" <|
                    expectation
                        [ FromString "9eM0Cv/GpoLdtOrRRcXFGhIcqSxiPwzwVjz5Qj9+EsAn2Rx6WH/DcnWgLA9tYtwIC91UvjpAIhgaPPGjzmCY9VLy/bZXU7dGS/Yp1jNetmsbgglNWRBGbzRnr8kkDUNNX3OKpqLAB2pooTbhYlFBGhWZ2j00opJUcuoyjW1LkeklT/PGQuyxYMbG4Msjf/XHziKtL251f0ZpV3RbfVpfOdlyWp6ebV+gQZwYuU25Z4QpRS1ANd7Ko17RgmqsfbfxEC5qFKCojBp4CFInqttee/PAES+E5I+4Kmn1shOYHmal8ASm61CGsGcnx/sKBqJVoafGqiuuy/vv+QlXoSeDbRG6kvOrABNpEVKSPcNKY8xgiVES1CM1ZsCgVT2YVDS2Ag8OOO/9W1r8638hbuWPrkd3HxR5ixM7r2T/Q07PWTo/q5YMTsIWs/ecw3hrW1/wCq78MbqkEBoERHlTO7fSGlzXU+L/SPV6Qt/LXalfoGnX77M5cuOfh8AuT1vvmoYqMttPwh2aFIAA3S7/4B8hlsU2BZV/019Qh/aRrl/li807qOMvVcUYk1VE8fx9JmPQKKEJYQTDuc3crZsEmEgzosKQ4MtUz024OmNI3gmw/AMGZxtde7BKtTcooNf+SWKvkKBq6z16qYvphISln6Xwzm7yl7NoNKJ6nUlfqtPPePZJcuNMdQNU70ZhEHQNyaRiQezok4OhELQZFE9/T9InBjgx/Qo=" ]
                        [ HexDigest "e67c0c12a5e85c3ca79e1ca862ee662d6497cca1", Base64Digest "5nwMEqXoXDynnhyoYu5mLWSXzKE=" ]
                , test "random string 2" <|
                    expectation
                        [ FromString "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" ]
                        [ HexDigest "fbadba9aa61b6ea574b013e05593f9711118b228", Base64Digest "+626mqYbbqV0sBPgVZP5cREYsig=" ]
                ]
            , describe "edge cases from 1.0.1"
                [ test "310 byte input" <|
                    expectation [ FromByteValues (List.repeat 64 54 ++ List.repeat 310 46) ]
                        [ HexDigest "08afccd24bce328ae74661653ca103df02cba690", Base64Digest "CK/M0kvOMornRmFlPKED3wLLppA=" ]
                , test "311 byte input" <|
                    expectation [ FromByteValues (List.repeat 64 54 ++ List.repeat 311 46) ]
                        [ HexDigest "bd8b2089549d57a05becbace5112c2c593b1af8b", Base64Digest "vYsgiVSdV6Bb7LrOURLCxZOxr4s=" ]
                , test "312 byte input" <|
                    expectation [ FromByteValues (List.repeat 64 54 ++ List.repeat 312 46) ]
                        [ HexDigest "c6045cfc2468675660d3ff788225229c6b7ab422", Base64Digest "xgRc/CRoZ1Zg0/94giUinGt6tCI=" ]
                ]
            ]
        , describe "bit operations"
            [ fuzz (Fuzz.intRange 0 0xFFFFFFFF) "rotate left" <|
                \value ->
                    let
                        n =
                            3
                    in
                    value
                        |> rotateLeftBy n
                        |> rotateLeftBy (32 - n)
                        |> Expect.equal value
            , fuzz (Fuzz.tuple ( Fuzz.intRange 0 0xFFFFFFFF, Fuzz.intRange 0 32 )) "rotate right" <|
                \( value, n ) ->
                    value
                        |> rotateRightBy n
                        |> rotateRightBy (32 - n)
                        |> Expect.equal value
            , test "small sigma 1" <|
                \_ ->
                    let
                        y =
                            3806512014
                    in
                    rotateRightBy 17 y
                        |> Bitwise.xor (rotateRightBy 19 y)
                        |> Bitwise.xor (Bitwise.shiftRightZfBy 10 y)
                        |> Bitwise.shiftRightZfBy 0
                        |> Expect.equal 965612957
            , test "right rotations 1" <|
                \_ -> rotateRightBy 17 3806512014 |> Expect.equal 1640460657
            , test "right rotations 2" <|
                \_ -> rotateRightBy 19 3806512014 |> Expect.equal 1483856988
            , test "right rotations 3" <|
                \_ -> Bitwise.shiftRightZfBy 10 3806512014 |> Expect.equal 3717296
            , test "xor 1" <|
                \_ -> Bitwise.xor 1640460657 1483856988 |> Expect.equal 968273197
            , test "xor 2" <|
                \_ ->
                    Bitwise.xor 968273197 3820533936
                        |> Bitwise.shiftRightZfBy 0
                        |> Expect.equal 3658356125
            , fuzz digestFuzzer "calculate the new a" <|
                \{ a, b, c, d, e } ->
                    let
                        f =
                            b

                        k =
                            c

                        int =
                            d

                        old =
                            rotateLeftBy 5 a
                                |> Bitwise.and 0xFFFFFFFF
                                |> (+) f
                                |> Bitwise.and 0xFFFFFFFF
                                |> (+) e
                                |> Bitwise.and 0xFFFFFFFF
                                |> (+) k
                                |> Bitwise.and 0xFFFFFFFF
                                |> (+) int
                                |> Bitwise.and 0xFFFFFFFF
                                |> Bitwise.shiftRightZfBy 0

                        new =
                            Bitwise.or (Bitwise.shiftRightZfBy (32 - 5) a) (Bitwise.shiftLeftBy 5 a)
                                |> (+) f
                                |> (+) e
                                |> (+) k
                                |> (+) int
                                |> Bitwise.shiftRightZfBy 0
                    in
                    new
                        |> Expect.equal old
            ]
        ]



-- CREATING TESTS


expectation : List Input -> List ExpectedOutput -> () -> Expectation
expectation inputs outputs _ =
    case inputs of
        [] ->
            Expect.fail "No inputs given"

        input :: otherInputs ->
            let
                digest =
                    toDigest input
            in
            if List.any (toDigest >> (/=) digest) otherInputs then
                [ "Not all inputs produced same output."
                , "Given inputs:"
                ]
                    ++ List.map debugInput (input :: inputs)
                    |> String.join "\n"
                    |> Expect.fail

            else
                case List.filter (not << isDigest digest) outputs of
                    [] ->
                        Expect.pass

                    failedOutputs ->
                        [ "Not all outputs matched digest."
                        , "Expected: " ++ SHA1.toHex digest ++ " / " ++ SHA1.toBase64 digest
                        , "Failed expected outputs:"
                        ]
                            ++ List.map debugOutput failedOutputs
                            |> String.join "\n"
                            |> Expect.fail


fromCAVS : Int -> ( String, List Int ) -> Test
fromCAVS testNumber ( expectedHex, byteValues ) =
    test ("test " ++ String.fromInt testNumber ++ ": " ++ expectedHex) <|
        expectation
            [ FromByteValues byteValues ]
            [ HexDigest expectedHex ]



-- FUZZERS


inputFuzzer : Fuzzer (List Input)
inputFuzzer =
    Fuzz.map
        (\string ->
            [ FromString string
            , FromByteValues (String.UTF8.toBytes string)
            , FromBytes (Encode.encode (Encode.string string))
            ]
        )
        Fuzz.string


digestFuzzer : Fuzzer Digest
digestFuzzer =
    Fuzz.map5 Digest
        (Fuzz.intRange 0 0xFFFFFFFF)
        (Fuzz.intRange 0 0xFFFFFFFF)
        (Fuzz.intRange 0 0xFFFFFFFF)
        (Fuzz.intRange 0 0xFFFFFFFF)
        (Fuzz.intRange 0 0xFFFFFFFF)



-- DIGEST HELPERS


toDigest : Input -> SHA1.Digest
toDigest input =
    case input of
        FromByteValues byteValues ->
            SHA1.fromByteValues byteValues

        FromString string ->
            SHA1.fromString string

        FromBytes bytes ->
            SHA1.fromBytes bytes


isDigest : SHA1.Digest -> ExpectedOutput -> Bool
isDigest digest expectedOuptut =
    case expectedOuptut of
        HexDigest hex ->
            hex == SHA1.toHex digest

        Base64Digest base64 ->
            base64 == SHA1.toBase64 digest

        ByteValuesDigest byteValues ->
            byteValues == SHA1.toByteValues digest

        BytesDigest bytes ->
            bytes == SHA1.toBytes digest


debugInput : Input -> String
debugInput input =
    case input of
        FromByteValues byteValues ->
            "  * byte values: 0x" ++ String.concat (List.map (Hex.toString >> String.padLeft 2 '0') byteValues)

        FromString string ->
            "  * string: " ++ string

        FromBytes bytes ->
            "  * bytes: " ++ String.fromInt (Bytes.width bytes) ++ " bytes"


debugOutput : ExpectedOutput -> String
debugOutput output =
    case output of
        HexDigest hex ->
            "  * hex: " ++ hex

        Base64Digest base64 ->
            "  * base64: " ++ base64

        ByteValuesDigest byteValues ->
            "  * byte values: 0x" ++ String.concat (List.map (Hex.toString >> String.padLeft 2 '0') byteValues)

        BytesDigest bytes ->
            "  * bytes: " ++ String.fromInt (Bytes.width bytes) ++ " bytes"



-- BITWISE HELPERS


rotateLeftBy : Int -> Int -> Int
rotateLeftBy amount i =
    Bitwise.or (Bitwise.shiftRightZfBy (32 - amount) i) (Bitwise.shiftLeftBy amount i)
        |> Bitwise.shiftRightZfBy 0


rotateRightBy : Int -> Int -> Int
rotateRightBy amount i =
    Bitwise.or (Bitwise.shiftLeftBy (32 - amount) i) (Bitwise.shiftRightZfBy amount i)
        |> Bitwise.shiftRightZfBy 0



-- BYTES


byteEncoder : Encoder
byteEncoder =
    Encode.unsignedInt8 0


kilobyteEncoder : Encoder
kilobyteEncoder =
    Encode.sequence (List.repeat 1024 byteEncoder)


megabyteEncoder : Encoder
megabyteEncoder =
    Encode.sequence (List.repeat 1024 kilobyteEncoder)


thirtyMegabytes : Bytes
thirtyMegabytes =
    Encode.encode (Encode.sequence (List.repeat 30 megabyteEncoder))
