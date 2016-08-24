CLANG_BIN=`xcrun --sdk iphoneos --find clang`
SDK=`xcrun --sdk iphoneos --show-sdk-path`

CLANG_BASE = $(CLANG_BIN) -isysroot $(SDK) 
CLANG_ARCH = -arch armv7 -arch armv7s -arch arm64
CLANG_FRAMEWORK = -framework Foundation

all: dumpdecrypted.dylib

dumpdecrypted.dylib: *.m 
	$(CLANG_BASE) $(CLANG_ARCH) $(CLANG_FRAMEWORK) -dynamiclib -o $@ $^

clean:
	rm -f *.o dumpdecrypted.dylib
