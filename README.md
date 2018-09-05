# Work in progress! Does not work!

# elm-sha1

Calculates SHA-1 message digests.

```elm
import SHA1

-- SHA1.hash : String -> SHA1.Digest
digest = SHA1.hash "string"

-- SHA1.toString : SHA1.Digest -> String
Debug.log "SHA1 of \"string\"" (SHA1.toString digest)
```
