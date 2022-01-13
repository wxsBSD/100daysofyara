#!/usr/bin/awk -f

{
  if ($2 in files) {
    files[$2 ] = files[$2] "," $1
  } else {
    files[$2] = $1
  }
}

END {
  for (file in files) {
    print file "\t" files[file]
  }
}
