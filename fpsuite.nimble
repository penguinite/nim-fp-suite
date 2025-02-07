# Package

version       = "0.1.0"
author        = "penguinite"
description   = "A suite of nim programs to help reduce Nim false positives!"
license       = "BSD-3-Clause"
srcDir        = "src"
binDir        = "bin"
bin           = @["rescan", "fetch", "generate", "all", "archive"]

# Dependencies

requires "nim >= 2.0.0"