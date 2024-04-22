import std/[os, parsecsv]

var p: CsvParser
p.open("virustotal links")
while readRow(p):
  when defined(debug):
    discard execShellCmd("echo " & p.row[1])
  else:
    discard execShellCmd("xdg-open " & p.row[1])
close(p)