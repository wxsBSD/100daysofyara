#!/bin/awk -f 

!/^0x/ {
  if (length(strings) > 0) {
    for (string in strings) {
      print string ": " strings[string];
    }
  }
  delete strings
  print;
}

/^0x/ {
  split($1, fields, ":");
  strings[fields[2]]++;
}

END {
  for (string in strings) {
    print string ": " strings[string];
  }
}
