# Host harness for multisig.h / psbt_passthrough.h / psbt.h (multisig fields).
#   make          build + run under UBSan, then ASan, then python cross-check
#   make vectors  regenerate ms_vectors.h with embit (pip install embit)
# Compiles the REAL src/ headers: -I../../src. Needs libmbedtls-dev on the host
# (mbedtls 2.28 or 3.x both work; the deprecation warnings are silenced).
CXX   ?= g++
SRC    = ../../src
WARN   = -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -Wno-unused-variable -Wno-deprecated-declarations -Wno-misleading-indentation
INC    = -Ihostshim -I$(SRC) $(EXTRA_INC)
LIBS   = -lmbedtls -lmbedcrypto
UBSAN  = -fsanitize=undefined -fsanitize=integer-divide-by-zero -g -O1
ASAN   = -fsanitize=address -fno-omit-frame-pointer -g -O1

.PHONY: all vectors clean
all:
	@$(CXX) $(UBSAN) $(WARN) $(INC) -o t_ms_ub test_multisig.cpp hostshim/host_globals.cpp $(LIBS)
	@./t_ms_ub > ub.log 2>&1; s=$$?; cat ub.log; \
	  if grep -q "runtime error" ub.log; then echo " UBSan: FINDINGS"; grep "runtime error" ub.log | sort -u; exit 1; else echo " UBSan: clean"; fi; \
	  [ $$s -eq 0 ] || exit $$s
	@$(CXX) $(ASAN) $(WARN) $(INC) -o t_ms_as test_multisig.cpp hostshim/host_globals.cpp $(LIBS)
	@./t_ms_as > as.log 2>&1 && echo " ASan:  clean" || { echo " ASan: FINDINGS"; cat as.log; exit 1; }
	@python3 verify_output.py out_ab.hex

vectors:
	@python3 gen_vectors.py && cp vectors/ms_vectors.h . 2>/dev/null || true

clean:
	@rm -f t_ms_ub t_ms_as *.log out_ab.hex
