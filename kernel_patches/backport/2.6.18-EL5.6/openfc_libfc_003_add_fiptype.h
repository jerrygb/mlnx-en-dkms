diff -Naur a/include/scsi/fc/fc_fip.h b/include/scsi/fc/fc_fip.h
--- a/include/scsi/fc/fc_fip.h	2010-06-23 10:53:54.007580000 -0700
+++ b/include/scsi/fc/fc_fip.h	2010-06-23 11:17:32.000000000 -0700
@@ -22,6 +22,13 @@
  * http://www.t11.org/ftp/t11/pub/fc/bb-5/08-543v1.pdf
  */
 
+/*
+ * The FIP ethertype eventually goes in net/if_ether.h.
+ */
+#ifndef ETH_P_FIP
+#define ETH_P_FIP	0x8914  /* FIP Ethertype */
+#endif
+
 #define FIP_DEF_PRI	128	/* default selection priority */
 #define FIP_DEF_FC_MAP	0x0efc00 /* default FCoE MAP (MAC OUI) value */
 #define FIP_DEF_FKA	8000	/* default FCF keep-alive/advert period (mS) */
