![Apache MINA SSHD](https://mina.apache.org/staticresources/images/header-sshd.png "Apache MINA SSHD")
# Apache MINA SSHD
Apache SSHD is a 100% pure java library to support the SSH protocols on both the client and server side. This library is based on [Apache MINA](http://mina.apache.org/), a scalable and high performance asynchronous IO library. SSHD does not really aim at being a replacement for the SSH client or SSH server from Unix operating systems, but rather provides support for Java based applications requiring SSH support.
# Set up an SSH client in 5 minutes
SSHD is designed to easily allow setting up and using an SSH client in a few simple steps. The client needs to be configured and then started before it can be used to connect to an SSH server. There are a few simple steps for creating a client instance - for more more details refer to the `SshClient` class.
## Creating an instance of the `SshClient` class
This is simply done by calling
```java
SshClient client = SshClient.setupDefaultClient();
```
The call will create an instance with a default configuration suitable for most use cases - including ciphers, compression, MACs, key exchanges, signatures, etc... If your code requires some special configuration, you can look at the code for `setupDefaultClient` and `checkConfig` as a reference for available options and configure the SSH client the way you need.
## Set up client side security
The SSH client contains some security related configuration that one needs to consider
### `ServerKeyVerifier`
`client.setServerKeyVerifier(...);` sets up the server key verifier. As part of the SSH connection initialization protocol, the server proves its "identity" by presenting a public key. The client can examine the key (e.g., present it to the user via some UI) and decide whether to trust the server and continue with the connection setup. By default the client is initialized with an `AcceptAllServerKeyVerifier` that simply logs a warning that an un-verified server key was accepted. There are other out-of-the-box verifiers available in the code:
* `RejectAllServerKeyVerifier` - rejects all server key - usually used in tests or as a fallback verifier if none of it predecesors validated the server key
* `RequiredServerKeyVerifier` - accepts only **one** specific server key (similar to certificate pinning for SSL)
* `KnownHostsServerKeyVerifier` - uses the [known_hosts](https://en.wikibooks.org/wiki/OpenSSH/Client_Configuration_Files#Public_Keys_from_other_Hosts_.E2.80.93_.7E.2F.ssh.2Fknown_hosts) file to validate the server key. One can use this class + some existing code to **update** the file when new servers are detected and their keys are accepted.

Of course, one can implement the verifier in whatever other manner is suitable for the specific code needs.
### ClientIdentityLoader/KeyPairProvider
One can set up the public/private keys to be used in case a password-less authentication is needed. By default, the client is configured to automatically detect and use the identity files residing in the user's *~/.ssh* folder (e.g., *id_rsa*, *id_ecdsa*) and present them as part of the authentication process. **Note:** if the identity files are encrypted via a password, one must configure a `FilePasswordProvider` so that the code can decrypt them before using and presenting them to the server as part of the authentication process. Reading key files in PEM format (including encrypted ones) requires that the [Bouncy Castle](https://www.bouncycastle.org/) supporting artifacts be available in the code's classpath.
# Embedding an SSHD server instance in 5 minutes
SSHD is designed to be easily embedded in your application as an SSH server. SSH Server needs to be configured before it can be started. Essentially, there are a few simple steps for creating the server - for more details refer to the `SshServer` class.
## Creating an instance of the `SshServer` class
Creating an instance of `SshServer` is as simple as creating a new object
```java
SshServer sshd = SshServer.setUpDefaultServer();
```
It will configure the server with sensible defaults for ciphers, macs, key exchange algorithm, etc... If you want a different behavior, you can look at the code of the `setUpDefaultServer` as well as `checkConfig` methods as a reference for available options and configure the SSH server the way you need.
## Configuring the server instance
There are a few things that needs to be configured on the server before being able to actually use it:
* Port - `sshd.setPort(22);` - sets the listen port for the server instance. If not set explicitly then a **random** free port is selected by the O/S. In any case, once the server is `start()`-ed one can query the instance as to the assigned port via `sshd.getPort()`.

In this context, the listen bind address can also be specified explicitly via `sshd.setHost(...some IP address...)` that causes the server to bind to a specific network address rather than all addresses (the default). Using "0.0.0.0" as the bind address is also tantamount to binding to all addresses.

* `KeyPairProvider` - `sshd.setKeyPairProvider(...);` - sets the host's private keys used for key exchange with clients as well as representing the host's "identities". There are several choices - one can load keys from standard PEM files or generate them in the code.  It's usually a good idea to save generated keys, so that if the SSHD server is restarted, the same keys will be used to authenticate the server and avoid the warning the clients might get if the host keys are modified. **Note**: loading or saving key files in PEM format requires  that the [Bouncy Castle](https://www.bouncycastle.org/) supporting artifacts be available in the code's classpath.

* `ShellFactory` - That's the part you will usually have to write to customize the SSHD server. The shell factory will be used to create a new shell each time a user logs in and wants to run an interactive shelll. SSHD provides a simple implementation that you can use if you want. This implementation will create a process and delegate everything to it, so it's mostly useful to launch the OS native shell. E.g.,
```java
sshd.setShellFactory(new ProcessShellFactory(new String[] { "/bin/sh", "-i", "-l" }));
```
Note that the `ShellFactory` is not required. If none is configured, any request for an interactive shell will be denied to users.

* `CommandFactory` - The `CommandFactory` provides the ability to run a **single** direct command at a time instead of an interactive session (it also uses a **different** channel type than shells). It can be used **in addition** to the `ShellFactory`.

SSHD provides a `CommandFactory` to support SCP that can be configured in the following way:
```java
sshd.setCommandFactory(new ScpCommandFactory());
```
You can also use the `ScpCommandFactory` on top of your own `CommandFactory` by placing your command factory as a **delegate** of the `ScpCommandFactory`. The `ScpCommandFactory` will intercept SCP commands and execute them by itself, and pass all other commands to (your) delegate `CommandFactory`
```java
sshd.setCommandFactory(new ScpCommandFactory(myCommandFactory));
```
Note that using a `CommandFactory` is also **optional**. If none is configured, any direct command sent by users will be rejected.
## Server side security setup
The SSHD server needs to be integrated and the security layer has to be customized to suit your needs. This layer is pluggable and use the following interfaces:
* `PasswordAuthenticator` for password based authentication
* `PublickeyAuthenticator` for key based authentication
* `KeyboardInteractiveAuthenticator` for user interactive authentication

These custom classes can be configured on the SSHD server using the respective setter methods:
```java
sshd.setPasswordAuthenticator(new MyPasswordAuthenticator());
sshd.setPublickeyAuthenticator(new MyPublickeyAuthenticator());
sshd.setKeyboardInteractiveAuthenticator(new MyKeyboardInteractiveAuthenticator());
...etc...
```
Several useful implementations are available that can be used as-is or extended in order to provide some custom behavior. In any case, the default initializations are:
* `DefaultAuthorizedKeysAuthenticator` - uses the _authorized_keys_ file the same way as the SSH daemon does
* `DefaultKeyboardInteractiveAuthenticator` - for password-based or interactive authentication. **Note:** this authenticator requires a `PasswordAuthenticator` to be configured since it delegates some of the functionality to it.

## Starting the Server
Once we have configured the server, one need only call `sshd.start();`. **Note**: once the server is started, all of the configurations (except the port) can still be *overridden* while the server is running (caveat emptor). In such cases, only **new** clients that connect to the server after the change will be affected - with the exception of the negotiation options (keys, macs, ciphers, etc...) which take effect the next time keys are re-exchanged, which can affect live sessions and not only new ones.