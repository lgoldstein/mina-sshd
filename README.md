![Apache MINA SSHD](https://mina.apache.org/staticresources/images/header-sshd.png "Apache MINA SSHD")
# Apache MINA SSHD
Apache SSHD is a 100% pure java library to support the SSH protocols on both the client and server side. This library is based on [Apache MINA](http://mina.apache.org/), a scalable and high performance asynchronous IO library. SSHD does not really aim at being a replacement for the SSH client or SSH server from Unix operating systems, but rather provides support for Java based applications requiring SSH support.
# Embedding SSHD in 5 minutes
SSHD is designed to be easily embedded in your application as an SSH server. SSH Server needs to be configured before it can be started. Essentially, there are a few simple steps for creating the server - for more details refer to the `SshServer` class.
## Creating an instance of SshServer class
Creating an instance of `SshServer` is as simple as creating a new object
```java
SshServer sshd = SshServer.setUpDefaultServer();
```
It will configure the server with sensible defaults for ciphers, macs, key exchange algorithm, etc... If you want a different behavior, you can look at the code of the `setUpDefaultServer` method and configure the SSH server the way you need.
## Configuring the Server
There are a few things that needs to be configured on the server before being able to actually use it:
* Port - `sshd.setPort(22);` - sets the listen port for the server instance. If not set explicitly then a **random** free port is selected by the O/S. In any case, once the server is `start()`-ed one can query the instance as to the assigned port via `sshd.getPort()`.

* `KeyPairProvider` - `sshd.setKeyPairProvider(...);` - sets the host's private keys used for key exchange with clients as well as representing the host's "identities". There are several choices - one can load keys from standard PEM files or generate them by the code.  It's usually a good idea to save generated keys, so that if the SSHD server is restarted, the same keys will be used to authenticate the server and avoid the uwarning the clients might get if the host keys are modified.

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
Note that usig a `CommandFactory` is also **optional**. If none is configured, any direct command sent by users will be rejected.
## Server side security setup
The SSHD server needs to be integrated and the security layer has to be customized to suit your needs. This layer is pluggable and use the following interfaces:
* `PasswordAuthenticator` for password based authentication
* `PublickeyAuthenticator` for key based authentication
* `KeyboardInteractiveAuthenticator` for user interactive authentication

Those custom classes can be configured on the SSHD server using the following code:
```java
SshServer sshd = SshServer.setUpDefaultServer();
sshd.setPasswordAuthenticator(new MyPasswordAuthenticator());
sshd.setPublickeyAuthenticator(new MyPublickeyAuthenticator());
sshd.setKeyboardInteractiveAuthenticator(new MyKeyboardInteractiveAuthenticator());
```
## Starting the Server
Once we have configured the server, one need only call `sshd.start();`. **Note**: once the server is started, all of the configurations (except the port) can still be *overridden* while the server is running (caveat emptor). In such cases, only **new** clients that connect to the server after the change will be affected - with the exception of the negotiation options (keys, macs, ciphers, etc...) which take effect the next time keys are re-exchanged, which can affect live sessions and not only new ones.