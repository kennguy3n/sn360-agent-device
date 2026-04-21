Name:           wda-agent
Version:        0.1.0
Release:        1%{?dist}
Summary:        Lightweight Wazuh-compatible security agent

License:        GPL-2.0-only
URL:            https://github.com/kennguy3n/sn360-agent-device

# The source tarball is expected to contain:
#   - wda-agent (release binary, already compiled)
#   - config.yaml
#   - wda-agent.service
# produced by `make rpm-srctar`.
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  systemd-rpm-macros
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
SN360 Desktop Agent (SDA) is a modular, cross-platform security agent
written in Rust. It provides file integrity monitoring, log collection,
system inventory, security configuration assessment, rootkit detection,
and active response, all optimized for sub-15 MB RAM and near-invisible
CPU impact on end-user devices.

%prep
%setup -q

%build
# binary is prebuilt; nothing to compile here

%install
rm -rf %{buildroot}
install -D -m 0755 wda-agent            %{buildroot}%{_bindir}/wda-agent
install -D -m 0644 config.yaml          %{buildroot}%{_sysconfdir}/sn360-desktop-agent/config.yaml
install -D -m 0644 wda-agent.service    %{buildroot}%{_unitdir}/wda-agent.service
install -d                              %{buildroot}%{_sysconfdir}/sn360-desktop-agent/sca
install -d                              %{buildroot}%{_sharedstatedir}/sn360-desktop-agent
install -d                              %{buildroot}%{_localstatedir}/log/sn360-desktop-agent

%files
%attr(0755, root, root)     %{_bindir}/wda-agent
%dir                        %{_sysconfdir}/sn360-desktop-agent
%dir                        %{_sysconfdir}/sn360-desktop-agent/sca
%config(noreplace)          %{_sysconfdir}/sn360-desktop-agent/config.yaml
%{_unitdir}/wda-agent.service
%attr(0750, wda, wda) %dir  %{_sharedstatedir}/sn360-desktop-agent
%attr(0750, wda, wda) %dir  %{_localstatedir}/log/sn360-desktop-agent

%pre
getent group wda >/dev/null || groupadd -r wda
getent passwd wda >/dev/null || \
    useradd -r -g wda -d %{_sharedstatedir}/sn360-desktop-agent \
            -s /sbin/nologin -c "SN360 Desktop Agent" wda

# Migrate legacy wazuh-desktop-agent install paths from pre-rename builds
# so operators upgrading keep their configuration and state. Must run
# before rpm extracts the payload, otherwise the new directories (which
# are shipped in %files) already exist and the -e check below always
# short-circuits to skip.
for legacy_new in \
    "%{_sysconfdir}/wazuh-desktop-agent:%{_sysconfdir}/sn360-desktop-agent" \
    "%{_sharedstatedir}/wazuh-desktop-agent:%{_sharedstatedir}/sn360-desktop-agent" \
    "%{_localstatedir}/log/wazuh-desktop-agent:%{_localstatedir}/log/sn360-desktop-agent"
do
    src="${legacy_new%%:*}"
    dst="${legacy_new##*:}"
    if [ -d "$src" ] && [ ! -e "$dst" ]; then
        mkdir -p "$(dirname "$dst")"
        mv "$src" "$dst"
        echo "migrated $src -> $dst" >&2
    fi
done
exit 0

%post
%systemd_post wda-agent.service

%preun
%systemd_preun wda-agent.service

%postun
%systemd_postun_with_restart wda-agent.service
if [ "$1" -eq 0 ]; then
    # package uninstall (not an upgrade): clean up state dir
    rm -rf %{_sharedstatedir}/sn360-desktop-agent \
           %{_localstatedir}/log/sn360-desktop-agent
    getent passwd wda >/dev/null && userdel wda >/dev/null 2>&1 || :
    getent group  wda >/dev/null && groupdel wda >/dev/null 2>&1 || :
fi

%changelog
* Mon Apr 20 2026 SN360 Desktop Agent Contributors <security@example.com> - 0.1.0-1
- Initial RPM packaging (task P3.4).
