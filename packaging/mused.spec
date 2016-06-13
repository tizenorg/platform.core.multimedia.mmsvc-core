Name:       mused
Summary:    A Multimedia Daemon in Tizen Native API
Version:    0.1.2
Release:    2
Group:      System/Libraries
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1:    muse-server.service
Source2:    muse-server.socket
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

Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

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
%if 0%{?sec_build_binary_debug_enable}
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE -D_GNU_SOURCE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE -D_GNU_SOURCE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE -D_GNU_SOURCE"
%endif

MAJORVER=`echo %{version} | awk 'BEGIN {FS="."}{print $1}'`
cmake . -DCMAKE_INSTALL_PREFIX=/usr -DFULLVER=%{version} -DMAJORVER=${MAJORVER} -DLIBDIR=%{_libdir}


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


%post
/sbin/ldconfig

%postun -p /sbin/ldconfig


%files
%manifest mused.manifest
%{_libdir}/libmused.so.*
%{_datadir}/license/%{name}
%{_unitdir}/muse-server.service
%{_unitdir}/multi-user.target.wants/muse-server.service
%{_unitdir}/muse-server.socket
%{_unitdir}/sockets.target.wants/muse-server.socket
/usr/bin/*


%files devel
%{_includedir}/media/*.h
%{_libdir}/pkgconfig/*.pc
%{_libdir}/libmused.so
