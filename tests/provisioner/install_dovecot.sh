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

dovecot_username=$1
dovecot_password=$2

# Install dovecot when control binary doesn't exists
if [ -z `which dovecot` ]; then
    echo -n "Install dovecot... "
    apt-get install -y dovecot-pop3d > /dev/null
    echo "done"
fi

dovecot_configured="/etc/dovecot/configured"
dovecot_restart=0

if [ ! -f "$dovecot_configured" ]; then
    echo -n "Configure dovecot... "

    dovecot_master_config="/etc/dovecot/conf.d/10-master.conf"
    if [ ! -f "$dovecot_master_config.orig" ]; then
        cp "$dovecot_master_config" "$dovecot_master_config.orig"
    fi

    dovecot_auth_config="/etc/dovecot/conf.d/10-auth.conf"
    if [ ! -f "$dovecot_auth_config.orig" ]; then
        cp "$dovecot_auth_config" "$dovecot_auth_config.orig"
    fi

    dovecot_mail_config="/etc/dovecot/conf.d/10-mail.conf"
    if [ ! -f "$dovecot_mail_config.orig" ]; then
        cp "$dovecot_mail_config" "$dovecot_mail_config.orig"
    fi

    dovecot_logging_config="/etc/dovecot/conf.d/10-logging.conf"
    if [ ! -f "$dovecot_logging_config.orig" ]; then
        cp "$dovecot_logging_config" "$dovecot_logging_config.orig"
    fi

    dovecot_passwdfile_config="/etc/dovecot/conf.d/auth-passwdfile.conf.ext"
    if [ ! -f "$dovecot_passwdfile_config.orig" ]; then
        cp "$dovecot_passwdfile_config" "$dovecot_passwdfile_config.orig"
    fi

    port_config=$(grep '#port = 110' $dovecot_master_config)
    if [ -n "$port_config" ]; then
        sed -i 's/#port = 110/port = 11110/' "$dovecot_master_config"
        dovecot_restart=1
    fi

    config_auth=$(grep 'auth_mechanisms = plain' "$dovecot_auth_config")
    if [ -n "$config_auth" ]; then
        sed -i 's/auth_mechanisms = plain/auth_mechanisms = plain cram-md5/' "$dovecot_auth_config"
        dovecot_restart=1
    fi

    config_auth=$(grep '#!include auth-passwdfile.conf.ext' "$dovecot_auth_config")
    if [ -n "$config_auth" ]; then
        sed -i 's/#!include auth-passwdfile.conf.ext/!include auth-passwdfile.conf.ext/' "$dovecot_auth_config"
        dovecot_restart=1
    fi

    config_mail=$(grep '#mail_location =' "$dovecot_mail_config")
    if [ -n "$config_mail" ]; then
        sed -i 's/#mail_location =/mail_location = maildir:~\/Maildir/' "$dovecot_mail_config"
        dovecot_restart=1
    fi

    config_logging=$(grep '#log_path = syslog' "$dovecot_logging_config")
    if [ -n "$config_logging" ]; then
        sed -i 's/#log_path = syslog/log_path = \/var\/log\/dovecot.log/' "$dovecot_logging_config"
        dovecot_restart=1
    fi

    config_passwd=$(grep 'scheme=CRYPT' "$dovecot_passwdfile_config")
    if [ -n "$config_passwd" ]; then
        sed -i 's/scheme=CRYPT/scheme=cram-md5/' "$dovecot_passwdfile_config"
        dovecot_restart=1
    fi

    dovecot_passwdfile='/etc/dovecot/users'
    if [ ! -f "$dovecot_passwdfile" ]; then
        echo -n "$dovecot_username:" > $dovecot_passwdfile
        echo -ne "$dovecot_password\n$dovecot_password" | doveadm pw | sed 's/{CRAM-MD5}//' >> $dovecot_passwdfile
    fi

    touch $dovecot_configured
    echo "done"
fi

id "$dovecot_username" > /dev/null 2>&1
if [ $? -eq 1 ]; then
    echo -n "Adding user '$dovecot_username' with password '$dovecot_password'... "
    useradd --password "$dovecot_password" --user-group --groups mail "$dovecot_username" > /dev/null
    mkdir -p "/home/$dovecot_username/Maildir"
    mkdir -p "/home/$dovecot_username/mail"
    chown "$dovecot_username:$dovecot_username" "/home/$dovecot_username/Maildir"
    chown "$dovecot_username:$dovecot_username" "/home/$dovecot_username/mail"
    echo "done"
fi

if [ $dovecot_restart -eq 1 ]; then
    echo "Trigger restart of dovecot"
    service dovecot restart > /dev/null
fi
