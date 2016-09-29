
EXE = lbctl
SRC =: lbctl-utils.c
OBJS= lbctl-utils.o 
 
$(EXE): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)
#	$(CC) $(LDFLAGS) -o $@ $(OBJS)&& $(STRIP) lbctl-utils && ls -l lbctl-utils
 
ifeq ($(FULL_COMPILE), y)
sinclude $(SRC:.c=.d)
endif
 
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
 
%.d: %.c
	@$(CC) -MM $(CFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$
 
.PHONY: clean
clean:
	$(RM) $(OBJS) $(EXE)

