Name:       mused
Summary:    A Media Daemon library in Tizen Native API
Version:    0.1.1
Release:    0
Group:      Multimedia/Service
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1:    mused.service
Source2:    mused.socket
BuildRequires:  cmake
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(mm-common)
BuildRequires:  pkgconfig(iniparser)
BuildRequires:  pkgconfig(json-c)
BuildRequires:  pkgconfig(gstreamer-1.0)
BuildRequires:  pkgconfig(gstreamer-base-1.0)

Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description


%package devel
Summary:  A Media Daemon library in Tizen (Development)
Group:    Multimedia/Service
Requires: %{name} = %{version}-%{release}
Requires:  pkgconfig(mm-common)
Requires:  pkgconfig(iniparser)
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
cp mused-server %{buildroot}/usr/bin

%make_install

mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants
install -m 0644 %SOURCE1 %{buildroot}%{_libdir}/systemd/system/mused.service
ln -s ../mused.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/mused.service

mkdir -p %{buildroot}%{_libdir}/systemd/system/sockets.target.wants
install -m 0644 %SOURCE2 %{buildroot}%{_libdir}/systemd/system/mused.socket
ln -s ../mused.socket %{buildroot}%{_libdir}/systemd/system/sockets.target.wants/mused.socket

%post
/sbin/ldconfig
chown 200:200 %{_libdir}/systemd/system/mused.socket

%postun -p /sbin/ldconfig


%files
%manifest mused.manifest
%defattr(-,system,system,-)
%{_libdir}/libmused.so.*
%{_datadir}/license/%{name}
%{_libdir}/systemd/system/mused.service
%{_libdir}/systemd/system/multi-user.target.wants/mused.service
%{_libdir}/systemd/system/sockets.target.wants/mused.socket
%{_libdir}/systemd/system/mused.socket
%{_datadir}/mused/mused.conf
/usr/bin/*


%files devel
%defattr(-,system,system,-)
%{_includedir}/media/*.h
%{_libdir}/pkgconfig/*.pc
%{_libdir}/libmused.so
