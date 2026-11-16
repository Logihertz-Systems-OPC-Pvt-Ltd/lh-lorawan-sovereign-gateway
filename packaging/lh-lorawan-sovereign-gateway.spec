Name:           lh-lorawan-sovereign-gateway
Version:        0.1.0
Release:        1%{?dist}
Summary:        lh-lorawan - RFC 4493 AES-CMAC Message Integrity Code & Time-on-Air
License:        Apache-2.0
URL:            https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-lorawan-sovereign-gateway
Source0:        %{name}-%{version}-src.tar.gz
Packager:       Sameer Tawade <ops@logihertz.com>
BuildArch:      %{_arch}

%description
Cloud-free C11 air-gapped IN865/EU868 LoRaWAN packet forwarder & local OTAA Join Server with clean-room FIPS 197 AES-128, RFC 4493 AES-CMAC MIC verification, DevNonce/FCntUp anti-replay, and CSS Time-on-Air math.

%prep
%autosetup -n %{name}-0.1.0

%build
# Industrial clean-room build with zero external runtime dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

if [ -f bin/lh-lorawan ]; then
    install -m 0755 bin/lh-lorawan %{buildroot}%{_bindir}/lh-lorawan
elif [ -f lh-lorawan ]; then
    install -m 0755 lh-lorawan %{buildroot}%{_bindir}/lh-lorawan
fi

install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 SPEC.md %{buildroot}%{_docdir}/%{name}/SPEC.md
install -m 0644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -m 0644 NOTICE %{buildroot}%{_docdir}/%{name}/NOTICE

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/SPEC.md
%doc %{_docdir}/%{name}/NOTICE
%license %{_docdir}/%{name}/LICENSE

%changelog
* Mon Nov 16 2026 Sameer Tawade <ops@logihertz.com> - 0.1.0-1
- Initial production release for Logihertz Systems Ecosystem and STRUCT OS.
