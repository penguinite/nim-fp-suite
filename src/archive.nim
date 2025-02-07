import std/os
if not dirExists("json"):
  echo "No json folder to archive, run \"nimble run fetch\" first in order to fetch data."
  quit(1)

# Create the archive folder
createDir("archive")

let time = readFile("json/time")

proc colonToDot(s: string): string =
  for ch in s:
    case ch:
    of ':': result.add "."
    else: result.add ch

moveDir("json", "archive/data-" & colonToDot(time))