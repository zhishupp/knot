.. highlight:: console

knotd – Knot DNS server daemon
==============================

Synopsis
--------

:program:`kntimers` [*parameters*]

Description
-----------

Parameters
..........

**-c**, **--config** *file*
  Use a textual configuration file (default is :file:`@config_dir@/knot.conf`).

**-C**, **--confdb** *directory*
  Use a binary configuration database directory (default is :file:`@storage_dir@/confdb`).
  The default configuration database, if exists, has a preference to the default
  configuration file.

**-z**, **--zone** *zone name*
  Print timers for this zone.

**-a**, **--all** [*directory*]
  Print timers for all zones.

**-h**, **--help**
  Print the program help.

**-V**, **--version**
  Print the program version.
 
