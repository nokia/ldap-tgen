
include ../../../../Make.inc

SRCS		= fips186prf.c eapcrypto.c eapcommon.c eapsimlib.c

INCLUDES	= 

CFLAGS		+= -DEAPLIB -I../../../include  -I/3pp_openssl/src/include

all:	static dynamic

TARGET=$(LIBPREFIX)eap

STATIC_OBJS	= $(SRCS:.c=.o)
DYNAMIC_OBJS	= $(SRCS:.c=.lo)

$(STATIC_OBJS):  $(INCLUDES)
$(DYNAMIC_OBJS): $(INCLUDES)

#######################################################################
#
# define new rules
#
#######################################################################
%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.lo : %.c
	$(LIBTOOL) --mode=compile $(CC) $(CFLAGS) -c $<


$(TARGET).a: $(STATIC_OBJS)
	$(LIBTOOL) --mode=link $(LD) \
	-module -static $(CFLAGS) $^ -o $@ 


ifneq ($(USE_SHARED_LIBS),yes)
LINK_MODE=-static
endif

$(TARGET).la: $(DYNAMIC_OBJS)
	$(LIBTOOL) --mode=link $(CC) -release $(RADIUSD_VERSION) \
	-module $(LINK_MODE) $(CFLAGS) -o $@ -rpath $(libdir) $^ 

static: $(TARGET).a

dynamic: $(TARGET).la

clean:
	rm -f *.o *.lo $(TARGET).a $(TARGET).la
	rm -rf .libs

install: static dynamic
	$(LIBTOOL) --mode=install $(INSTALL) -c \
		$(TARGET).la $(R)$(libdir)/$(TARGET).la;
	rm -f $(R)$(libdir)/$(TARGET)-$(RADIUSD_VERSION).la;
	ln -s $(TARGET).la $(R)$(libdir)/$(TARGET)-$(RADIUSD_VERSION).la
