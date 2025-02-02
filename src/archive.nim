import std/os
if not dirExists("json"):
  echo "No json folder to archive, run \"nimble run fetch\" first in order to fetch data."
  quit(1)


# Create the archive folder
createDir("archive")

