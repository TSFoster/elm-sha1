BEGIN {
  count = 0
  printf "module Generated.%s exposing (tests)\n\n", filename
  print "tests ="
}

/^Msg = / {
  count++
  msg = $3
  sep = count == 1 ? "[" : ","
  sub(/\r/, "", msg)
  if (msg == "00") msg = ""
  msg = gensub(/(..)/, "0x\\1, ", "g", msg)
  sub(/, $/, "", msg)
}

/^MD = / {
  md=$3
  sub(/\r/, "", md)
  printf "  %s ( \"%s\", [ %s ] )\n", sep, md, msg
}

END {
  print "  ]"
}
