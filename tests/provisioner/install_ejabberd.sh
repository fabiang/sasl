#!/usr/bin/env bash

##
# Sasl library.
#
# Copyright (c) 2002-2003 Richard Heyes,
#               2014-2023 Fabian Grutschus
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# o Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
# o Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.|
# o The names of the authors may not be used to endorse or promote
#   products derived from this software without specific prior written
#   permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# @author Fabian Grutschus <f.grutschus@lubyte.de>
#

jabber_username=$1
jabber_password=$2

# Install ejabberd when control binary doesn't exists
if [ -z `which ejabberdctl` ]; then
    echo -n "Install ejabberd... "
    apt-get update > /dev/null
    apt-get install -y ejabberd > /dev/null
    dpkg --configure ejabberd > /dev/null 2>&1
    echo "done"
fi

ejabberd_config="/etc/ejabberd/ejabberd.yml"
ejabberd_configured="/etc/ejabberd/configured"
ejabberd_restart=0

if [ ! -f "$ejabberd_configured" ]; then
    echo -n "Configure ejabberd... "

    service ejabberd stop > /dev/null

    cp "$ejabberd_config" "$ejabberd_config.orig"

    port_config=$(grep '    port: 5222' $ejabberd_config)
    if [ -n "$port_config" ]; then
        sed -i 's/    port: 5222/    port: 15222/' "$ejabberd_config"
        ejabberd_restart=1
    fi

    host_config=$(grep '  - "localhost"' $ejabberd_config)
    if [ -n "$host_config" ]; then
        sed -i "s/  - \"localhost\"/  - \"$HOSTNAME\"/" "$ejabberd_config"
        ejabberd_restart=1
    fi

    digestMD5=$(grep 'disable_sasl_mechanisms: "digest-md5"' $ejabberd_config)
    if [ -n "$digestMD5" ]; then
        sed -i "s/disable_sasl_mechanisms: \"digest-md5\"/disable_sasl_mechanisms: \"\"/" "$ejabberd_config"
        ejabberd_restart=1
    fi

    authPlain=$(grep 'auth_password_format: scram' "$ejabberd_config")
    if [ -n "$authPlain" ]; then
        sed -i "s/auth_password_format: scram/auth_password_format: plain/" "$ejabberd_config"
        ejabberd_restart=1
    fi

    iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp -m tcp --dport 5222 -j ACCEPT
    iptables -A INPUT -p udp -m udp --dport 5222 -j ACCEPT
    iptables -A INPUT -p tcp -m tcp --dport 15222 -j ACCEPT
    iptables -A INPUT -p udp -m udp --dport 15222 -j ACCEPT
    iptables -A INPUT -p tcp -m tcp --dport 5223 -j ACCEPT
    iptables -A INPUT -p udp -m udp --dport 5223 -j ACCEPT
    iptables -A INPUT -p tcp -m tcp --dport 5269 -j ACCEPT
    iptables -A INPUT -p udp -m udp --dport 5269 -j ACCEPT
    iptables -A INPUT -p tcp -m tcp --dport 5280 -j ACCEPT
    iptables -A INPUT -p udp -m udp --dport 5280 -j ACCEPT
    iptables -A INPUT -p tcp -m tcp --dport 4369 -j ACCEPT
    iptables -A INPUT -p udp -m udp --dport 4369 -j ACCEPT
    iptables -A INPUT -p tcp -m tcp --dport 53873 -j ACCEPT

    touch $ejabberd_configured
    echo "done"
fi

if [ $ejabberd_restart -eq 1 ]; then
    echo "Trigger restart of ejabberd"
    service ejabberd restart > /dev/null
fi

# Adding users must be done after restarting the server, since hostname must be present
user_exists=$(ejabberdctl registered-users $HOSTNAME | grep "$jabber_username" )
if [ -z "$user_exists" ]; then
    echo -n "Register user '$jabber_username' with password '$jabber_password' at ejabberd... "

    # restart and wait before adding users, otherwise adding fails
    service ejabberd restart > /dev/null
    sleep 5

    ejabberdctl register "$jabber_username" "$HOSTNAME" "$jabber_password" > /dev/null
    echo "done"
fi
