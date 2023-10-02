#!/usr/bin/env sh

# TODO: if not needed remove xml-1.1.3
# the following one probably still requires "rapidxml" itself
# since the rock only contains the (binary version of the) binding
# to rapidxml
#luarocks install xml-1.1.3-1.linux-x86_64.rock >> /build.log 2>&1 || (cat /build.log && exit 1)

# why 2 xml libs?
apt install libxml2
# >> /build.log 2>&1 || (cat /build.log && exit 1)
luarocks install xmlua

# additionally run the default action of installing rockspec dependencies
/pongo/default-pongo-setup.sh