import std/[osproc, os]

discard execCmd("nimble run rescan")
echo "Waiting an hour for the rescans to finish"
sleep(3600000)
discard execCmd("nimble run fetch")
discard execCmd("nimble run generate")
discard execCmd("nimble run archive")