Name:       mused
Summary:    A Multimedia Daemon in Tizen Native API
Version:    0.1.2
Release:    3
Group:      System/Libraries
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1:    muse-server.service
Source2:    muse-server.socket
Source3:    muse-server.path
BuildRequires:  cmake
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(mm-common)
BuildRequires:  pkgconfig(capi-base-common)
BuildRequires:  pkgconfig(iniparser)
BuildRequires:  pkgconfig(json-c)
BuildRequires:  pkgconfig(gstreamer-1.0)
BuildRequires:  pkgconfig(gstreamer-base-1.0)
BuildRequires:  pkgconfig(libtbm)
BuildRequires: pkgconfig(cynara-client)
BuildRequires: pkgconfig(cynara-creds-socket)
BuildRequires: pkgconfig(cynara-session)
BuildRequires: pkgconfig(libtzplatform-config)


Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
Requires: security-config

%description


%package devel
Summary:  A Media Daemon library in Tizen (Development)
Group:    Multimedia/Service
Requires: %{name} = %{version}-%{release}
Requires:  pkgconfig(mm-common)
Requires:  pkgconfig(iniparser)
Requires: pkgconfig(libtbm)
%description devel

%prep
%setup -q


%build
export CFLAGS="$CFLAGS -DSYSCONFDIR=\\\"%{_sysconfdir}\\\""
export CXXFLAGS="$CXXFLAGS -DSYSCONFDIR=\\\"%{_sysconfdir}\\\""

%if 0%{?sec_build_binary_debug_enable}
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE -D_GNU_SOURCE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE -D_GNU_SOURCE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE -D_GNU_SOURCE"
%endif

MAJORVER=`echo %{version} | awk 'BEGIN {FS="."}{print $1}'`
cmake . -DCMAKE_INSTALL_PREFIX=/usr -DFULLVER=%{version} -DMAJORVER=${MAJORVER} -DLIBDIR=%{_libdir} -DTZ_SYS_DATA=%TZ_SYS_DATA

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp LICENSE.APLv2 %{buildroot}/usr/share/license/%{name}
mkdir -p %{buildroot}/usr/bin
cp muse-server %{buildroot}/usr/bin

%make_install

mkdir -p %{buildroot}%{_unitdir}/multi-user.target.wants
install -m 0644 %SOURCE1 %{buildroot}%{_unitdir}/muse-server.service
%install_service multi-user.target.wants muse-server.service

mkdir -p %{buildroot}%{_unitdir}/sockets.target.wants
install -m 0644 %SOURCE2 %{buildroot}%{_unitdir}/muse-server.socket
%install_service sockets.target.wants muse-server.socket

install -m 0644 %SOURCE3 %{buildroot}%{_unitdir}/muse-server.path

mkdir -p %{buildroot}/var/log/%{name}
mkdir -p -m 0770 %{buildroot}%{TZ_SYS_DATA}/%{name}

%post
/sbin/ldconfig

chown multimedia_fw:multimedia_fw %{TZ_SYS_DATA}/%{name}
chown multimedia_fw:multimedia_fw /var/log/%{name}
chsmack -a "System::Shared" %{TZ_SYS_DATA}/%{name}
chsmack -a "System::Shared" /var/log/%{name}

%postun -p /sbin/ldconfig


%files
%manifest mused.manifest
%{_libdir}/libmused.so.*
%{_datadir}/license/%{name}
%{_unitdir}/muse-server.service
%{_unitdir}/multi-user.target.wants/muse-server.service
%{_unitdir}/muse-server.socket
%{_unitdir}/sockets.target.wants/muse-server.socket
%{_unitdir}/muse-server.path
%{TZ_SYS_DATA}/%{name}
/var/log/%{name}
/usr/bin/*


%files devel
%{_includedir}/media/*.h
%{_libdir}/pkgconfig/*.pc
%{_libdir}/libmused.so
