CFLAGS := -O2 -Wall -Wextra -Wvla -Wsign-conversion -pedantic -std=c99
APPNAME := test_pbkdf2

ifeq ($(OS),Windows_NT)
	RM := del /Q
	CC := gcc
	EXT := .exe
endif

APP := $(APPNAME)$(EXT)
 
all: $(APP)

$(APP): test_pbkdf2.c pbkdf2_sha256.h
	$(CC) $(CFLAGS) -o $@ $<
 
clean:
	$(RM) $(APP)  
