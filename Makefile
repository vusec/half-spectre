CC = g++
CFLAGS+=-g -Wall -pedantic -Wextra --std=c++2a -no-pie
DFLAGS?=-DCONTENTION_JNE=0 -DCONTENTION_ALIGN=61 -DCONTENTION_N_JE=3 -DCONTENTION_N_JA=0 # TESTBED CONTENTION CONFIG
LDFLAGS += -lpthread -pthread -lm
SANITY_DFLAGS += -DSANITY
TARGET = preload_time
SRCDIR = src
OBJDIR = obj

SRC:=$(wildcard $(SRCDIR)/*.cc)
TMP:=$(SRC:$(SRCDIR)/%=obj/%)
OBJ:=$(TMP:.cc=.o)

all: $(OBJDIR) $(TARGET)

default:
	all

$(OBJDIR):
	mkdir -p $@

$(TARGET): $(OBJ)
	@echo "LD $@"
	$(CC) $(CFLAGS) $^ -o $@

$(OBJDIR)/%.o : $(SRCDIR)/%.cc $(SRCDIR)/%.h
	@echo "CC $<"
	@$(CC) $(CFLAGS) $(DFLAGS) -c -o $@ $<

sanity: DFLAGS += $(SANITY_DFLAGS)
sanity: clean $(OBJDIR) $(TARGET)

.PHONY: clean
clean:
	rm -rf $(OBJDIR)
	rm -f $(TARGET)
