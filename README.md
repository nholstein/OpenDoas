# OpenDoas: a portable version of OpenBSD's `doas` command

[`doas`](https://en.wikipedia.org/wiki/Doas) is a minimal replacement for the venerable `sudo`. It was
initially [written by Ted Unangst](http://www.tedunangst.com/flak/post/doas)
of the OpenBSD project to provide 95% of the features of `sudo` with a
fraction of the codebase.

## Building and Installation Warnings

There are a few steps you have to carefully consider before building and installing
OpenDoas:

* There are fewer eyes on random `doas` ports, just because `sudo` had a vulnerability
  does not mean random doas ports are more secure if they are not reviewed
  or [PAM](https://en.wikipedia.org/wiki/Pluggable_authentication_module) is configured incorrectly.
  * If you want to use PAM; You have to [configure PAM](#pam-configuration)
    and failing to do so correctly might leave a big open door.

* Use the `configure` script.
* Use the default make target.
* If you really want to install a setuid binary that depends on
  PAM being correctly configured, use the `make install` target
  to install the software.

## About the OpenDoas Port

This is not an official port/project from OpenBSD!

As much as possible I've attempted to stick to `doas` as tedu desired
it. As things stand it's essentially just code lifted from OpenBSD with
PAM or shadow based authentication glommed on to it.

Compatibility functions in libopenbsd come from OpenBSD directly
(`strtonum.c`, `reallocarray.c`, `strlcpy.c`, `strlcat.c`),
from openssh (`readpassphrase.c`) or from sudo (`closefrom.c`).

The PAM and shadow authentication code does not come from the OpenBSD project.

### PAM Configuration

I will not ship PAM configuration files, they are distribution specific and
its simply not safe or productive to ship and install those files.

If you want to use OpenDoas on your system and there is no package that
ships with a working PAM configuration file, then you have to write and
test it yourself.

A good starting point is probably the distribution maintained `/etc/pam.d/sudo`
file.

### Persist/Timestamp/Timeout

The persist feature is disabled by default and can be enabled with the
`--with-timestamp` configure flag.

This feature is new and potentially dangerous, in the original `doas`, a kernel API
is used to set and clear timeouts. This API is OpenBSD specific and no similar API
is available on other operating systems.

As a workaround, the persist feature is implemented using timestamp files
similar to `sudo`.

See the comment block in `timestamp.c` for an in-depth description on how
timestamps are created and checked to be as safe as possible.
