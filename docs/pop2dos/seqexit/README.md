# Experimental exit-copy snapshot (known failing)

This is the recovered worker attempt, not an accepted fix. On sub_29B99 the snapshot is emitted after the earlier AX publication, so the BX exit still uses the wrong value. The archived exact tests passed at the AST level but the three machine-vs-C witnesses in this directory failed. This change does not address the separate physical guest-stack store.
