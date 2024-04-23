# Package

version       = "0.1.0"
author        = "penguinite"
description   = "A suite of nim programs to help reduce Nim false positives!"
license       = "BSD-3-Clause"
srcDir        = "src"
bin           = @["fpsuite"]

# Dependencies

requires "nim >= 2.0.4"

import std/[os, envvars]

proc fetchKey(): string =
  # Order of priority:
  # Environment -> Files -> Command-line Params
  if existsEnv("VT_KEY"):
    result = getEnv("VT_KEY")
  if existsEnv("VIRUSTOTAL_KEY"):
    result = getEnv("VIRUSTOTAL_KEY")
  if fileExists("vt_key"):
    result = readFile("vt_key")
  if fileExists(".vt_key"):
    result = readFile(".vt_key")
  
  proc getKeyFromParams(): string =
    return commandLineParams()[high(commandLineParams())]
  if paramCount() > 0 and getKeyFromParams() != "fetch":
    result = getKeyFromParams()
  
  return result

task fetch, "Fetches latest data from VirusTotal":
  let virusTotalKey = fetchKey()
  when not defined(shutUp):
    echo "Using key: ", virusTotalKey
  exec "nimble -d:fetchAndLeave -d:virusTotalKey=\"" & virusTotalKey & "\" run fpsuite"

task generate, "Generate using pre-fetched data":
  exec "nimble -d:useFetchedData run fpsuite"

task fetchgen, "Fetch new data and generate":
  let virusTotalKey = fetchKey()
  when not defined(shutUp):
    echo "Using key: ", virusTotalKey
  exec "nimble -d:virusTotalKey=\"" & virusTotalKey & "\"run fpsuite"