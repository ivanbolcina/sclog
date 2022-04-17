# SCLOG 

## About

SCLOG stands for signed chained logger. It is a logger application that receives messages to REST endpoint. It then signs them using PKCS#11 signature method and chains the message to previous message. 

## How does it work

Application listens by default to http://localhost:2001/send and accepts JSON from client applications. See test/send.sh for an example. Then it finds previous log in DB (if it exists), and extracts its signature. Whole record is then binary serialized (using cbor) and signed with PKCS#11. This ensures that signature result is repetable. Only after that it is inserted into database.

## Configuration

See configuration.toml for configuration options.
See log.properties and log.tail.properties for logging options. For HSM configuration, see softhsm/softhsm.conf.

## Build

For building you need conan, cmake, GCC or similar. IDE: Visual Studio code or similar.

1. install conan package manager
2. change dir to "conan" and execute "conan install .."
3. build using cmake

## Running

First install some PKCS#11 driver. By default, you can use SoftHSM2. 

1. Start docker "docker-compose up". This starts up MySQL server.
2. Start application:
  - configuration files have to be in the current directory
  - start app with "sclog"
3. Test it using test/send.sh script.
4. Examine database table for newly added records.

## Licence

Apache Licence, version 2.0. See https://www.apache.org/licenses/LICENSE-2.0

