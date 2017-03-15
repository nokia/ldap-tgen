#! /bin/sh
#
# Author: Klaus.Franken@fth2.siemens.de
# Die Okt 12 10:05:41 EDT 1999
#
# Modified by:
# 1999/11/07 - Sebastien Godard <sebastien.godard@wanadoo.fr>
#	Now use '-d' option when starting sar.
# 2000/01/22 - Sebastien Godard <sebastien.godard@wanadoo.fr>
#	Rewritten from scratch. Call sadc instead of sar.
#
# /etc/rc.d/init.d/sysstat
#

# See how we were called.
case "$1" in
  start)
        echo -n "Calling the system activity data collector (sadc): "
        PREFIX/lib/sa/sadc -F -L - QUOTE
        echo
        ;;
  stop|status|restart|reload)
        ;;
  *)
        echo "Usage: sysstat {start|stop|status|restart|reload}"
        exit 1
esac

