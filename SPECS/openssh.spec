%global package_speccommit 8bc30558bfd6de018b6aeed060eb61a266877bb0
%global usver 9.8p1
%global xsver 1.2
%global xsrel %{xsver}%{?xscount}%{?xshash}
# start the release from openssh_rel as other packages requires

# XCP-ng sub release number
%define xcpng_subrel 1

%global WITH_SELINUX 0

%global _hardened_build 1

%if 0%{?xenserver} < 9
# OpenSSH privilege separation requires a user & group ID
%global sshd_uid    74
%global sshd_gid    74
%endif

# Do we want to link against a static libcrypto? (1=yes 0=no)
%global static_libcrypto 0

# Build position-independent executables (requires toolchain support)?
%global pie 1

# Do we want kerberos5 support (1=yes 0=no)
%global kerberos5 1

# Do we want libedit support
%global libedit 1

# Whether to build pam_ssh_agent_auth
%global pam_ssh_agent 0

# Reserve options to override askpass settings with:
# rpm -ba|--rebuild --define 'skip_xxx 1'
%global no_gnome_askpass 1

# Options for static OpenSSL link:
# rpm -ba|--rebuild --define "static_openssl 1"
%{?static_openssl:%global static_libcrypto 1}

# Do not forget to bump pam_ssh_agent_auth release if you rewind the main package release to 1
%global openssh_ver 9.8p1
%global openssh_rel 4
%global pam_ssh_agent_ver 0.10.4
%global pam_ssh_agent_rel 10

Summary: An open source implementation of SSH protocol version 2
Name:    openssh
Version: %{openssh_ver}
Release: %{?xsrel}.%{xcpng_subrel}~XCPNG2710.4%{?dist}
URL: http://www.openssh.com/portable.html
#URL1: https://github.com/jbeverly/pam_ssh_agent_auth/
Source0: openssh-9.8p1.tar.gz
Source2: sshd.pam
Source4: pam_ssh_agent_auth-0.10.4.tar.gz
Source5: pam_ssh_agent-rmheaders
Source6: ssh-keycat.pam
Source7: sshd.sysconfig
Source9: sshd@.service
Source10: sshd.socket
Source11: sshd.service
Source12: sshd-keygen@.service
Source13: sshd-keygen
Source15: sshd-keygen.target
Source19: openssh-server-systemd-sysusers.conf
Source22: parallel_test.sh
Source23: parallel_test.Makefile
Patch0: openssh-7.8p1-role-mls.patch
Patch1: openssh-6.6p1-privsep-selinux.patch
Patch2: openssh-6.6p1-keycat.patch
Patch3: openssh-6.6p1-allow-ip-opts.patch
Patch4: openssh-5.9p1-ipv6man.patch
Patch5: openssh-5.8p2-sigpipe.patch
Patch6: openssh-7.2p2-x11.patch
Patch7: openssh-5.1p1-askpass-progress.patch
Patch8: openssh-4.3p2-askpass-grab-info.patch
Patch9: openssh-7.7p1-redhat.patch
Patch10: openssh-7.8p1-UsePAM-warning.patch
Patch11: openssh-8.0p1-gssapi-keyex.patch
Patch12: openssh-6.6p1-force_krb.patch
Patch13: openssh-7.7p1-gssapi-new-unique.patch
Patch14: openssh-7.2p2-k5login_directory.patch
Patch15: openssh-9.6p1-gsskex-new-api.patch
Patch16: openssh-6.6p1-kuserok.patch
Patch17: openssh-6.4p1-fromto-remote.patch
Patch18: openssh-6.6.1p1-selinux-contexts.patch
Patch19: openssh-6.6.1p1-log-in-chroot.patch
Patch20: openssh-6.6.1p1-scp-non-existing-directory.patch
Patch21: openssh-6.6p1-GSSAPIEnablek5users.patch
Patch22: openssh-6.8p1-sshdT-output.patch
Patch23: openssh-6.7p1-sftp-force-permission.patch
Patch24: openssh-7.2p2-s390-closefrom.patch
Patch25: openssh-7.3p1-x11-max-displays.patch
Patch26: openssh-7.6p1-cleanup-selinux.patch
Patch27: openssh-7.5p1-sandbox.patch
Patch28: openssh-8.0p1-pkcs11-uri.patch
Patch29: openssh-7.8p1-scp-ipv6.patch
Patch30: openssh-8.0p1-crypto-policies.patch
Patch31: openssh-9.3p1-merged-openssl-evp.patch
Patch32: openssh-8.0p1-openssl-kdf.patch
Patch33: openssh-8.2p1-visibility.patch
Patch34: openssh-8.2p1-x11-without-ipv6.patch
Patch35: openssh-8.0p1-keygen-strip-doseol.patch
Patch36: openssh-8.0p1-preserve-pam-errors.patch
Patch37: openssh-8.7p1-scp-kill-switch.patch
Patch38: openssh-8.7p1-recursive-scp.patch
Patch39: openssh-8.7p1-minrsabits.patch
Patch40: openssh-8.7p1-ibmca.patch
Patch41: openssh-7.6p1-audit.patch
Patch42: openssh-7.1p2-audit-race-condition.patch
Patch43: openssh-9.0p1-audit-log.patch
Patch44: openssh-8.7p1-audit-hostname.patch
Patch45: openssh-7.7p1-fips.patch
Patch46: openssh-8.7p1-ssh-manpage.patch
Patch47: openssh-8.7p1-negotiate-supported-algs.patch
Patch48: openssh-9.0p1-evp-fips-dh.patch
Patch49: openssh-9.0p1-evp-fips-ecdh.patch
Patch50: openssh-8.7p1-nohostsha1proof.patch
Patch51: openssh-9.6p1-pam-rhost.patch
Patch52: openssh-6.7p1-coverity.patch

# XCP-ng patches
Patch1000: openssh-7.4p1-CVE-2025-26465-Fix-cases-where-error-codes-were-not-correc.patch

Source24: ssh_config
Source25: sshd_config

License: BSD-3-Clause AND BSD-2-Clause AND ISC AND SSH-OpenSSH AND ssh-keyscan AND sprintf AND LicenseRef-Fedora-Public-Domain AND X11-distribute-modifications-variant
Requires: /sbin/nologin

BuildRequires: autoconf, automake, perl-interpreter, perl-generators, zlib-devel
BuildRequires: audit-libs-devel >= 2.0.5
BuildRequires: util-linux, groff
BuildRequires: pam-devel
BuildRequires: openssl-devel >= 0.9.8j
BuildRequires: perl-podlators
BuildRequires: systemd-devel
BuildRequires: gcc make
BuildRequires: p11-kit-devel
Obsoletes: openssh-ldap < 8.3p1-4
Obsoletes: openssh-cavs < 8.4p1-5

%if %{kerberos5}
BuildRequires: krb5-devel
%endif

%if %{libedit}
BuildRequires: libedit-devel ncurses-devel
%endif

%if %{WITH_SELINUX}
Requires: libselinux >= 2.3-5
BuildRequires: libselinux-devel >= 2.3-5
Requires: audit-libs >= 1.0.8
BuildRequires: audit-libs >= 1.0.8
%endif

# for tarball signature verification
BuildRequires: gnupg2

%package clients
Summary: An open source SSH client applications
Requires: openssh = %{version}-%{release}

%package server
Summary: An open source SSH server daemon
Requires: openssh = %{version}-%{release}
Requires(pre): /usr/sbin/useradd
Requires: pam >= 1.0.1-3
%{?systemd_requires}

%package keycat
Summary: A mls keycat backend for openssh
Requires: openssh = %{version}-%{release}

%package askpass
Summary: A passphrase dialog for OpenSSH and X
Requires: openssh = %{version}-%{release}

%package sk-dummy
Summary: OpenSSH SK driver for test purposes
Requires: openssh = %{version}-%{release}

%package -n pam_ssh_agent_auth
Summary: PAM module for authentication with ssh-agent
Version: %{pam_ssh_agent_ver}
Release: %{?xsrel}%{?dist}
License: BSD-3-Clause AND BSD-2-Clause AND ISC AND SSH-OpenSSH AND ssh-keyscan AND sprintf AND LicenseRef-Fedora-Public-Domain AND X11-distribute-modifications-variant AND OpenSSL

%description
SSH (Secure SHell) is a program for logging into and executing
commands on a remote machine. SSH is intended to replace rlogin and
rsh, and to provide secure encrypted communications between two
untrusted hosts over an insecure network. X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's version of the last free version of SSH, bringing
it up to date in terms of security and features.

This package includes the core files necessary for both the OpenSSH
client and server. To make this package useful, you should also
install openssh-clients, openssh-server, or both.

%description clients
OpenSSH is a free version of SSH (Secure SHell), a program for logging
into and executing commands on a remote machine. This package includes
the clients necessary to make encrypted connections to SSH servers.

%description server
OpenSSH is a free version of SSH (Secure SHell), a program for logging
into and executing commands on a remote machine. This package contains
the secure shell daemon (sshd). The sshd daemon allows SSH clients to
securely connect to your SSH server.

%description keycat
OpenSSH mls keycat is backend for using the authorized keys in the
openssh in the mls mode.

%description askpass
OpenSSH is a free version of SSH (Secure SHell), a program for logging
into and executing commands on a remote machine. This package contains
an X11 passphrase dialog for OpenSSH.

%description sk-dummy
This package contains a test SK driver used for OpenSSH test purposes

%description -n pam_ssh_agent_auth
This package contains a PAM module which can be used to authenticate
users using ssh keys stored in a ssh-agent. Through the use of the
forwarding of ssh-agent connection it also allows to authenticate with
remote ssh-agent instance.

The module is most useful for su and sudo service stacks.

%prep
%autosetup -p1 -a 4

%if %{pam_ssh_agent}
pushd pam_ssh_agent_auth-pam_ssh_agent_auth-%{pam_ssh_agent_ver}
# Remove duplicate headers and library files
rm -f $(cat %{SOURCE5})
popd
%endif

# Override the ssh/sshd configuration
cp -f %{SOURCE24} %{SOURCE25} .


autoreconf
pushd pam_ssh_agent_auth-pam_ssh_agent_auth-%{pam_ssh_agent_ver}
autoreconf
popd

%build
%set_build_flags
# the -fvisibility=hidden is needed for clean build of the pam_ssh_agent_auth
# it is needed for lib(open)ssh build too since it is linked to the pam module too
CFLAGS="$CFLAGS -fvisibility=hidden"; export CFLAGS
%if %{pie}
CFLAGS="$CFLAGS -fpic"
SAVE_LDFLAGS="$LDFLAGS"
LDFLAGS="$LDFLAGS -pie -z relro -z now"

export CFLAGS
export LDFLAGS

%endif
%if %{kerberos5}
if test -r /etc/profile.d/krb5-devel.sh ; then
	source /etc/profile.d/krb5-devel.sh
fi
krb5_prefix=`krb5-config --prefix`
if test "$krb5_prefix" != "%{_prefix}" ; then
	CPPFLAGS="$CPPFLAGS -I${krb5_prefix}/include -I${krb5_prefix}/include/gssapi"; export CPPFLAGS
	CFLAGS="$CFLAGS -I${krb5_prefix}/include -I${krb5_prefix}/include/gssapi"
	LDFLAGS="$LDFLAGS -L${krb5_prefix}/%{_lib}"; export LDFLAGS
else
	krb5_prefix=
	CPPFLAGS="-I%{_includedir}/gssapi"; export CPPFLAGS
	CFLAGS="$CFLAGS -I%{_includedir}/gssapi"
fi
%endif

%configure \
	--sysconfdir=%{_sysconfdir}/ssh \
	--libexecdir=%{_libexecdir}/openssh \
	--datadir=%{_datadir}/openssh \
	--with-default-path=/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin \
	--with-superuser-path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin \
	--with-privsep-path=%{_datadir}/empty.sshd \
	--disable-strip \
	--without-zlib-version-check \
	--with-ipaddr-display \
	--with-pie=no \
	--without-hardening `# The hardening flags are configured by system` \
	--with-systemd \
	--with-default-pkcs11-provider=yes \
	--disable-security-key \
	--with-security-key-builtin=no \
	--with-pam \
%if %{WITH_SELINUX}
	--with-selinux --with-audit=linux \
	--with-sandbox=seccomp_filter \
%endif
%if %{kerberos5}
	--with-kerberos5${krb5_prefix:+=${krb5_prefix}} \
%else
	--without-kerberos5 \
%endif
%if %{libedit}
	--with-libedit
%else
	--without-libedit
%endif

%if %{static_libcrypto}
perl -pi -e "s|-lcrypto|%{_libdir}/libcrypto.a|g" Makefile
%endif

%make_build
make regress/misc/sk-dummy/sk-dummy.so


%if %{pam_ssh_agent}
pushd pam_ssh_agent_auth-pam_ssh_agent_auth-%{pam_ssh_agent_ver}
LDFLAGS="$SAVE_LDFLAGS"
%configure --without-selinux \
	--libexecdir=/%{_libdir}/security \
	--with-mantype=man \
	--without-ssl-engine \
	--without-openssl-header-check `# The check is broken`
%make_build
popd
%endif

%check
%{SOURCE22} %{SOURCE23}  # ./parallel_tests.sh parallel_tests.Makefile

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p -m755 $RPM_BUILD_ROOT%{_sysconfdir}/ssh
mkdir -p -m755 $RPM_BUILD_ROOT%{_sysconfdir}/ssh/ssh_config.d
mkdir -p -m755 $RPM_BUILD_ROOT%{_sysconfdir}/ssh/sshd_config.d
mkdir -p -m755 $RPM_BUILD_ROOT%{_libexecdir}/openssh
%make_install

# %%config(noreplace) is removed that leads to no .rpmnew file created,
# so need to duplicate one for writing back to on-disk config file.
# This is temporary workaround, and can be deleted in future.
cp -p $RPM_BUILD_ROOT%{_sysconfdir}/ssh/ssh_config $RPM_BUILD_ROOT%{_sysconfdir}/ssh/ssh_config.dup
cp -p $RPM_BUILD_ROOT%{_sysconfdir}/ssh/sshd_config $RPM_BUILD_ROOT%{_sysconfdir}/ssh/sshd_config.dup

install -d $RPM_BUILD_ROOT/etc/pam.d/
install -d $RPM_BUILD_ROOT/etc/sysconfig/
install -d $RPM_BUILD_ROOT%{_libexecdir}/openssh
install -m644 %{SOURCE6} $RPM_BUILD_ROOT/etc/pam.d/ssh-keycat
install -m644 %{SOURCE2} $RPM_BUILD_ROOT/etc/pam.d/sshd
install -m644 %{SOURCE7} $RPM_BUILD_ROOT/etc/sysconfig/sshd
install -d -m755 $RPM_BUILD_ROOT/%{_unitdir}
install -m644 %{SOURCE9} $RPM_BUILD_ROOT/%{_unitdir}/sshd@.service
install -m644 %{SOURCE10} $RPM_BUILD_ROOT/%{_unitdir}/sshd.socket
install -m644 %{SOURCE11} $RPM_BUILD_ROOT/%{_unitdir}/sshd.service
install -m644 %{SOURCE12} $RPM_BUILD_ROOT/%{_unitdir}/sshd-keygen@.service
install -m644 %{SOURCE15} $RPM_BUILD_ROOT/%{_unitdir}/sshd-keygen.target
install -m744 %{SOURCE13} $RPM_BUILD_ROOT/%{_libexecdir}/openssh/sshd-keygen
install -m755 contrib/ssh-copy-id $RPM_BUILD_ROOT%{_bindir}/
install contrib/ssh-copy-id.1 $RPM_BUILD_ROOT%{_mandir}/man1/
install -d -m711 ${RPM_BUILD_ROOT}/%{_datadir}/empty.sshd
install -p -D -m 0644 %{SOURCE19} %{buildroot}%{_sysusersdir}/openssh-server.conf

%if ! %{no_gnome_askpass}
install contrib/gnome-ssh-askpass $RPM_BUILD_ROOT%{_libexecdir}/openssh/gnome-ssh-askpass
%endif

%if ! %{no_gnome_askpass}
ln -s gnome-ssh-askpass $RPM_BUILD_ROOT%{_libexecdir}/openssh/ssh-askpass
install -m 755 -d $RPM_BUILD_ROOT%{_sysconfdir}/profile.d/
install -m 755 contrib/redhat/gnome-ssh-askpass.csh $RPM_BUILD_ROOT%{_sysconfdir}/profile.d/
install -m 755 contrib/redhat/gnome-ssh-askpass.sh $RPM_BUILD_ROOT%{_sysconfdir}/profile.d/
%endif

%if %{no_gnome_askpass}
rm -f $RPM_BUILD_ROOT/etc/profile.d/gnome-ssh-askpass.*
%endif

perl -pi -e "s|$RPM_BUILD_ROOT||g" $RPM_BUILD_ROOT%{_mandir}/man*/*

%if %{pam_ssh_agent}
pushd pam_ssh_agent_auth-pam_ssh_agent_auth-%{pam_ssh_agent_ver}
%make_install
popd
%endif

install -m 755 -d $RPM_BUILD_ROOT%{_libdir}/sshtest/
install -m 755 regress/misc/sk-dummy/sk-dummy.so $RPM_BUILD_ROOT%{_libdir}/sshtest

%pre server
%if 0%{?xenserver} < 9
getent group sshd >/dev/null || groupadd -g %{sshd_uid} -r sshd || :
getent passwd sshd >/dev/null || \
  useradd -c "Privilege-separated SSH" -u %{sshd_uid} -g sshd \
  -s /sbin/nologin -r -d /usr/share/empty.sshd sshd 2> /dev/null || :

# Handle rpm updating here; RPU case is handled in host-installer
find /etc/ssh -maxdepth 1 -name "ssh_host_*_key" -type f -exec chmod g-r {} \; -exec chown root:root {} \;
%else
%sysusers_create_compat %{SOURCE19}
%endif

%post server
%systemd_post sshd.service sshd.socket

%preun server
%systemd_preun sshd.service sshd.socket

%postun server
%systemd_postun_with_restart sshd.service

%posttrans server
cat %{_sysconfdir}/ssh/sshd_config.dup > %{_sysconfdir}/ssh/sshd_config
systemctl daemon-reload
if systemctl is-active --quiet sshd; then
    systemctl restart sshd
fi

%posttrans clients
cat %{_sysconfdir}/ssh/ssh_config.dup > %{_sysconfdir}/ssh/ssh_config

%files
%license LICENCE
%doc CREDITS ChangeLog OVERVIEW PROTOCOL* README README.platform README.privsep README.tun README.dns TODO
%attr(0755,root,root) %dir %{_sysconfdir}/ssh
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ssh/moduli
%attr(0755,root,root) %{_bindir}/ssh-keygen
%attr(0644,root,root) %{_mandir}/man1/ssh-keygen.1*
%attr(0755,root,root) %dir %{_libexecdir}/openssh
%attr(4555,root,root) %{_libexecdir}/openssh/ssh-keysign
%attr(0644,root,root) %{_mandir}/man8/ssh-keysign.8*

%files clients
%attr(0755,root,root) %{_bindir}/ssh
%attr(0644,root,root) %{_mandir}/man1/ssh.1*
%attr(0755,root,root) %{_bindir}/scp
%attr(0644,root,root) %{_mandir}/man1/scp.1*
%attr(0644,root,root) %{_sysconfdir}/ssh/ssh_config
%attr(0644,root,root) %{_sysconfdir}/ssh/ssh_config.dup
%dir %attr(0755,root,root) %{_sysconfdir}/ssh/ssh_config.d/
%attr(0644,root,root) %{_mandir}/man5/ssh_config.5*
%attr(0755,root,root) %{_bindir}/ssh-agent
%attr(0755,root,root) %{_bindir}/ssh-add
%attr(0755,root,root) %{_bindir}/ssh-keyscan
%attr(0755,root,root) %{_bindir}/sftp
%attr(0755,root,root) %{_bindir}/ssh-copy-id
%attr(0755,root,root) %{_libexecdir}/openssh/ssh-pkcs11-helper
%attr(0755,root,root) %{_libexecdir}/openssh/ssh-sk-helper
%attr(0644,root,root) %{_mandir}/man1/ssh-agent.1*
%attr(0644,root,root) %{_mandir}/man1/ssh-add.1*
%attr(0644,root,root) %{_mandir}/man1/ssh-keyscan.1*
%attr(0644,root,root) %{_mandir}/man1/sftp.1*
%attr(0644,root,root) %{_mandir}/man1/ssh-copy-id.1*
%attr(0644,root,root) %{_mandir}/man8/ssh-pkcs11-helper.8*
%attr(0644,root,root) %{_mandir}/man8/ssh-sk-helper.8*

%files keycat
%doc HOWTO.ssh-keycat
%attr(0755,root,root) %{_libexecdir}/openssh/ssh-keycat
%attr(0644,root,root) %config(noreplace) /etc/pam.d/ssh-keycat

%files server
%dir %attr(0711,root,root) %{_datadir}/empty.sshd
%attr(0755,root,root) %{_sbindir}/sshd
%attr(0755,root,root) %{_libexecdir}/openssh/sshd-session
%attr(0755,root,root) %{_libexecdir}/openssh/sftp-server
%attr(0755,root,root) %{_libexecdir}/openssh/sshd-keygen
%attr(0644,root,root) %{_mandir}/man5/sshd_config.5*
%attr(0644,root,root) %{_mandir}/man5/moduli.5*
%attr(0644,root,root) %{_mandir}/man8/sshd.8*
%attr(0644,root,root) %{_mandir}/man8/sftp-server.8*
%attr(0600,root,root) %{_sysconfdir}/ssh/sshd_config
%attr(0600,root,root) %{_sysconfdir}/ssh/sshd_config.dup
%dir %attr(0700,root,root) %{_sysconfdir}/ssh/sshd_config.d/
%attr(0644,root,root) /etc/pam.d/sshd
%attr(0640,root,root) /etc/sysconfig/sshd
%attr(0644,root,root) %{_unitdir}/sshd.service
%attr(0644,root,root) %{_unitdir}/sshd@.service
%attr(0644,root,root) %{_unitdir}/sshd.socket
%attr(0644,root,root) %{_unitdir}/sshd-keygen@.service
%attr(0644,root,root) %{_unitdir}/sshd-keygen.target
%attr(0644,root,root) %{_sysusersdir}/openssh-server.conf

%if ! %{no_gnome_askpass}
%files askpass
%attr(0644,root,root) %{_sysconfdir}/profile.d/gnome-ssh-askpass.*
%attr(0755,root,root) %{_libexecdir}/openssh/gnome-ssh-askpass
%attr(0755,root,root) %{_libexecdir}/openssh/ssh-askpass
%endif

%files sk-dummy
%attr(0755,root,root) %{_libdir}/sshtest/sk-dummy.so

%if %{pam_ssh_agent}
%files -n pam_ssh_agent_auth
%license pam_ssh_agent_auth-pam_ssh_agent_auth-%{pam_ssh_agent_ver}/OPENSSH_LICENSE
%attr(0755,root,root) %{_libdir}/security/pam_ssh_agent_auth.so
%attr(0644,root,root) %{_mandir}/man8/pam_ssh_agent_auth.8*
%endif

%changelog
* Tue Feb 03 2026 Philippe Coval <philippe.coval@vates.tech> - 9.8p1-1.2.1
- Refresh XCP-ng patches:
  - Drop unnecessary hardening and gssapi patches
  - Replace CVE-2025-26465 backport with upstream patch from 9.9p1
- Sync with 9.8p1-1.2
- *** Upstream changelog ***
- * Fri Nov 07 2025 Alex Brett <alex.brett@citrix.com> - 9.8p1-1.2
- - CA-420416: Remove diffie-hellman-group14-sha1 KexAlgorithm
- * Thu Jan 02 2025 Deli Zhang <deli.zhang@cloud.com> - 9.8p1-1.1
- - CA-400917: Disable PerSourcePenalties
- - CA-401322: Revert sshd.pam to xs8 default
- - CA-401322: Ensure new config files applied
- * Fri Sep 13 2024 Deli Zhang <deli.zhang@citrix.com> - 9.8p1-1
- - CP-50298: Upgrade to version 9.8p1
- * Wed Jul 31 2024 Lin Liu <lin.liu@citrix.com> - 8.8p1-3
- - CP-50477: Customize ssh configurations
- * Mon Sep 25 2023 Lin Liu <lin.liu@citrix.com> - 8.8p1-2
- - CP-45435: Permit root ssh login
- * Thu Jul 20 2023 Lin Liu <lin.liu@citrix.com> - 8.8p1-1
- - First imported release

* Mon Apr 28 2025 Yann Dirson <yann.dirson@vates.tech> - 7.4p1-23.3.3 + 0.10.3-2.23.3.3
- Rebuild against ncurses 6.4-6.20240309 to pull abi5 (compat) libs

* Mon Mar 17 2025 Lucas Ravagnier <lucas.ravagnier@vates.tech> - 7.4p1-23.3.2 + 0.10.3-2.23.3.2
- Fix CVE-2025-26465 - Fix cases where error codes were not correctly set

* Mon Aug 12 2024 Samuel Verschelde <stormi-xcp@ylix.fr> - 7.4p1-23.3.1 + 0.10.3-2.23.3.1
- Sync with 7.4p1-23.3 + 0.10.3-2.23.3
- *** Upstream changelog ***
- * Tue Jul 02 2024 Ross Lagerwall <ross.lagerwall@citrix.com> - 7.4p1-23.3 + 0.10.3-2
- - CP-50166: Remove libsystemd integration
- - CA-395182: Fix CVE-2024-6387 - use of non-async-signal-safe fn in sighandler

* Tue Apr 30 2024 Thierry Escande <thierry.escande@vates.tech> - 7.4p1-23.2.1 + 0.10.3-2.23.2.1
- Harden default ciphers and algorithms
- Disable GSSAPIAuthentication in sshd_config
- Remove build dependency on xauth (used for X11 forwarding not supported on XCP-ng hosts)
- Make use of xcpng_subrel macro for versioning
- Disable gnome_askpass
- Add BuildRequires for gcc

* Wed Jan 24 2024 Alex Brett <alex.brett@cloud.com> - 7.4p1-23.2 + 0.10.3-2
- Fix for CVE-2023-48795: Add strict key exchange extension

* Thu Dec 14 2023 Alex Brett <alex.brett@cloud.com> - 7.4p1-23.1 + 0.10.3-2
- Imported openssh-7.4p1-23.el7_9 from CentOS, including:
- Fix for CVE-2023-38408
- Fix for CVE-2021-41617
- Fix for CVE-2018-15473
- Fix for CVE-2017-15906

