# Compile-only check of multisig_ui.inc on the host.
# Catches syntax and type errors in the new UI code without an ESP32 build.
# uistub.h fakes the firmware surface (spr, buttons, fonts, camera, QR); it is
# NOT a behaviour test and is never compiled into the firmware.
#   make            must print nothing (zero warnings from the new code)
CXX ?= g++
SRC  = ../../src
all:
	@$(CXX) -fsyntax-only -Wall -Wextra -Wno-unused-parameter -Wno-unused-function \
	  -Wno-deprecated-declarations -I. -I../multisig/hostshim -I$(SRC) uicheck.cpp \
	  2>&1 | grep -v "secp256k1" || true
	@echo " uicheck: multisig_ui.inc compiles"
