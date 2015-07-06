Name:       mused
Summary:    A Media Daemon library in Tizen Native API
Version:    0.1.1
Release:    0
Group:      TO_BE/FILLED_IN
License:    TO BE FILLED IN
Source0:    %{name}-%{version}.tar.gz
Source1:    mused.service
Source2:    mused.socket
BuildRequires:  cmake
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(mm-common)
BuildRequires:  pkgconfig(iniparser)
BuildRequires:  pkgconfig(json-c)
#BuildRequires:  pkgconfig(mm-session)
#BuildRequires:  pkgconfig(mm-sound)
#BuildRequires:  pkgconfig(mm-player)
#BuildRequires:  pkgconfig(mm-ta)
#BuildRequires:  pkgconfig(capi-base-common)
#BuildRequires:  pkgconfig(capi-media-sound-manager)
#BuildRequires:  pkgconfig(gstreamer-0.10)
#BuildRequires:  pkgconfig(gstreamer-plugins-base-0.10)
#BuildRequires:  pkgconfig(gstreamer-interfaces-0.10)
#BuildRequires:  pkgconfig(gstreamer-app-0.10)
#BuildRequires:  pkgconfig(appcore-efl)
#BuildRequires:  pkgconfig(elementary)
#BuildRequires:  pkgconfig(ecore)
#BuildRequires:  pkgconfig(evas)
#BuildRequires:  pkgconfig(ecore-x)
#BuildRequires:  pkgconfig(capi-media-tool)
#BuildRequires:  pkgconfig(libtbm)
#BuildRequires:  pkgconfig(mmutil-imgp)
#BuildRequires:  pkgconfig(audio-session-mgr)
#BuildRequires:  pkgconfig(vconf)
#BuildRequires:  pkgconfig(icu-i18n)
#BuildRequires:  pkgconfig(utilX)

Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description


%package devel
Summary:  A Media Daemon library in Tizen (Development)
Group:    TO_BE/FILLED_IN
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
cmake . -DCMAKE_INSTALL_PREFIX=/usr -DFULLVER=%{version} -DMAJORVER=${MAJORVER}


make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
#mkdir -p %{buildroot}/opt/usr/devel
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
