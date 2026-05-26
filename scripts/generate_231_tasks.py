#!/usr/bin/env python3
"""
Generate supplement task files for all RHEL-09-231xxx filesystem/mount checks.
Run once to produce task files; re-run if templates need updating.

Usage: python3 scripts/generate_231_tasks.py
"""

import json
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TASKS_DIR = os.path.join(REPO, 'roles', 'rhel9_stig_supplement', 'tasks')

with open(os.path.join(REPO, 'files', 'rules.json')) as f:
    RULES = json.load(f)

SEV_MAP = {'high': 'CAT I', 'medium': 'CAT II', 'low': 'CAT III'}

# check_type and parameters for each rule
RULE_PARAMS = {
    'RHEL-09-231010': ('separate_fs', '/home'),
    'RHEL-09-231015': ('separate_fs', '/tmp'),
    'RHEL-09-231020': ('separate_fs', '/var'),
    'RHEL-09-231025': ('separate_fs', '/var/log'),
    'RHEL-09-231030': ('separate_fs', '/var/log/audit'),
    'RHEL-09-231035': ('separate_fs', '/var/tmp'),
    'RHEL-09-231040': ('autofs',),
    'RHEL-09-231045': ('mount_opt', '/home',          'nodev'),
    'RHEL-09-231050': ('mount_opt', '/home',          'nosuid'),
    'RHEL-09-231055': ('mount_opt', '/home',          'noexec'),
    'RHEL-09-231065': ('nfs_opt',   'nodev'),
    'RHEL-09-231070': ('nfs_opt',   'noexec'),
    'RHEL-09-231075': ('nfs_opt',   'nosuid'),
    'RHEL-09-231080': ('removable_opt', 'noexec'),
    'RHEL-09-231085': ('removable_opt', 'nodev'),
    'RHEL-09-231090': ('removable_opt', 'nosuid'),
    'RHEL-09-231095': ('mount_opt', '/boot',          'nodev'),
    'RHEL-09-231100': ('mount_opt', '/boot',          'nosuid'),
    'RHEL-09-231105': ('boot_efi_opt', 'nosuid'),
    'RHEL-09-231110': ('mount_opt', '/dev/shm',       'nodev'),
    'RHEL-09-231115': ('mount_opt', '/dev/shm',       'noexec'),
    'RHEL-09-231120': ('mount_opt', '/dev/shm',       'nosuid'),
    'RHEL-09-231125': ('mount_opt', '/tmp',           'nodev'),
    'RHEL-09-231130': ('mount_opt', '/tmp',           'noexec'),
    'RHEL-09-231135': ('mount_opt', '/tmp',           'nosuid'),
    'RHEL-09-231140': ('mount_opt', '/var',           'nodev'),
    'RHEL-09-231145': ('mount_opt', '/var/log',       'nodev'),
    'RHEL-09-231150': ('mount_opt', '/var/log',       'noexec'),
    'RHEL-09-231155': ('mount_opt', '/var/log',       'nosuid'),
    'RHEL-09-231160': ('mount_opt', '/var/log/audit', 'nodev'),
    'RHEL-09-231165': ('mount_opt', '/var/log/audit', 'noexec'),
    'RHEL-09-231170': ('mount_opt', '/var/log/audit', 'nosuid'),
    'RHEL-09-231175': ('mount_opt', '/var/tmp',       'nodev'),
    'RHEL-09-231180': ('mount_opt', '/var/tmp',       'noexec'),
    'RHEL-09-231185': ('mount_opt', '/var/tmp',       'nosuid'),
    'RHEL-09-231190': ('encryption',),
    'RHEL-09-231200': ('nodev_nonroot',),
}


# ─── helpers ─────────────────────────────────────────────────────────────────

def rule_header(sid):
    r = RULES[sid]
    cat = SEV_MAP.get(r['severity'], r['severity'])
    sev = r['severity'].capitalize()
    ccis = ', '.join(r['ccis']) if r['ccis'] else ''
    return (f"---\n"
            f"# {sid} | {r['group_id']}\n"
            f"# {r['title']}\n"
            f"# {cat} ({sev}) | {ccis}\n")


def vname(sid):
    """RHEL-09-231010 -> _231010_result"""
    return '_' + sid.split('-')[2] + '_result'


def subst(tmpl, **kwargs):
    """Simple placeholder substitution using ##KEY## markers."""
    for k, v in kwargs.items():
        tmpl = tmpl.replace(f'##{k}##', v)
    return tmpl


def write_file(sid, content):
    path = os.path.join(TASKS_DIR, f'{sid}.yml')
    with open(path, 'w') as f:
        f.write(content)
    print(f'  {sid}.yml')


# ─── templates ───────────────────────────────────────────────────────────────

SEPARATE_FS_TMPL = """\

# Checks that ##MP## is mounted as a separate filesystem.

- name: ##SID## | check ##MP## is a separate filesystem
  shell: awk '$2 == "##MP##"' /proc/mounts
  register: ##VNAME##
  changed_when: false
  tags: [validate]

- name: ##SID## | record ##MP## separate filesystem status
  set_fact:
    supp_facts: "{{ supp_facts | combine({
      '##SID##': {
        'status': 'not_a_finding' if (##VNAME##.stdout | trim) else 'open',
        'finding_details':
          '/proc/mounts entry: '
          ~ (##VNAME##.stdout | trim if ##VNAME##.stdout | trim else '(not a separate mount - FINDING)')
          ~ '\\nResult: '
          ~ ('not_a_finding - ##MP## is a separate filesystem'
             if (##VNAME##.stdout | trim)
             else 'OPEN - ##MP## is not on a separate filesystem'),
        'comments': 'Requires a dedicated partition or logical volume. Configure in /etc/fstab.'
      }
    }) }}"
  tags: [validate]
"""

MOUNT_OPT_TMPL = """\

# Checks that ##MP## is mounted with the ##OPT## option.
# An empty result means ##MP## is not separately mounted, which is also a finding.

- name: ##SID## | get ##MP## mount options
  shell: awk '$2 == "##MP##" { print $4 }' /proc/mounts
  register: ##VNAME##
  changed_when: false
  tags: [validate]

- name: ##SID## | record ##MP## ##OPT## mount option status
  set_fact:
    supp_facts: "{{ supp_facts | combine({
      '##SID##': {
        'status':
          'not_a_finding'
          if ('##OPT##' in (##VNAME##.stdout | default('')))
          else 'open',
        'finding_details':
          '##MP## mount options: '
          ~ (##VNAME##.stdout | default('') | trim
             if ##VNAME##.stdout | default('') | trim
             else '(not separately mounted - FINDING)')
          ~ '\\nResult: '
          ~ ('not_a_finding - ##OPT## is set on ##MP##'
             if ('##OPT##' in (##VNAME##.stdout | default('')))
             else 'OPEN - ##OPT## not found in ##MP## mount options'),
        'comments': 'Add ##OPT## to the ##MP## entry in /etc/fstab and remount.'
      }
    }) }}"
  tags: [validate]
"""

AUTOFS_TMPL = """\

# autofs must be masked or disabled. Not applicable if not installed.

- name: ##SID## | check autofs service state
  command: systemctl is-enabled autofs
  register: ##VNAME##
  changed_when: false
  failed_when: false
  tags: [validate]

- name: ##SID## | record autofs status
  set_fact:
    supp_facts: "{{ supp_facts | combine({
      '##SID##': {
        'status':
          'not_applicable'
          if 'Failed to get unit file state' in (##VNAME##.stdout | default(''))
             or ##VNAME##.rc == 1 and not (##VNAME##.stdout | trim)
          else ('not_a_finding'
                if (##VNAME##.stdout | trim) in ['masked', 'disabled']
                else 'open'),
        'finding_details':
          'systemctl is-enabled autofs: '
          ~ (##VNAME##.stdout | trim if ##VNAME##.stdout | trim else '(not installed)')
          ~ '\\nResult: '
          ~ ('not_applicable - autofs is not installed'
             if 'Failed to get unit file state' in (##VNAME##.stdout | default(''))
                or ##VNAME##.rc == 1 and not (##VNAME##.stdout | trim)
             else ('not_a_finding - autofs is ' ~ (##VNAME##.stdout | trim)
                   if (##VNAME##.stdout | trim) in ['masked', 'disabled']
                   else 'OPEN - autofs is enabled; must be masked or disabled')),
        'comments': 'To remediate: sudo systemctl mask autofs'
      }
    }) }}"
  tags: [validate]
"""

NFS_OPT_TMPL = """\

# N/A if no NFS mounts are configured in /etc/fstab.
# All NFS fstab entries must have the ##OPT## option.

- name: ##SID## | get all NFS entries from fstab
  shell: grep -Ei '^[^#].*\\bnfs[0-9]?\\b' /etc/fstab || true
  register: ##VNAME##_all
  changed_when: false
  tags: [validate]

- name: ##SID## | get NFS fstab entries missing ##OPT##
  shell: grep -Ei '^[^#].*\\bnfs[0-9]?\\b' /etc/fstab | grep -v '##OPT##' || true
  register: ##VNAME##_bad
  changed_when: false
  tags: [validate]

- name: ##SID## | record NFS ##OPT## status
  set_fact:
    supp_facts: "{{ supp_facts | combine({
      '##SID##': {
        'status':
          'not_applicable' if not (##VNAME##_all.stdout | trim)
          else ('not_a_finding' if not (##VNAME##_bad.stdout | trim) else 'open'),
        'finding_details':
          'NFS fstab entries: '
          ~ (##VNAME##_all.stdout | trim if ##VNAME##_all.stdout | trim else '(none - not applicable)')
          ~ '\\nEntries missing ##OPT##: '
          ~ (##VNAME##_bad.stdout | trim if ##VNAME##_bad.stdout | trim else '(none)')
          ~ '\\nResult: '
          ~ ('not_applicable - no NFS mounts configured'
             if not (##VNAME##_all.stdout | trim)
             else ('not_a_finding - all NFS mounts have ##OPT##'
                   if not (##VNAME##_bad.stdout | trim)
                   else 'OPEN - one or more NFS mounts missing ##OPT##')),
        'comments': 'Add ##OPT## to all NFS entries in /etc/fstab.'
      }
    }) }}"
  tags: [validate]
"""

REMOVABLE_OPT_TMPL = """\

# Checks that removable media fstab entries (vfat, fat, ntfs, exfat) have ##OPT##.

- name: ##SID## | get removable media entries from fstab
  shell: grep -Ei '^[^#]' /etc/fstab | grep -Ei '\\b(vfat|fat|ntfs|exfat)\\b' || true
  register: ##VNAME##_all
  changed_when: false
  tags: [validate]

- name: ##SID## | get removable media fstab entries missing ##OPT##
  shell: grep -Ei '^[^#]' /etc/fstab | grep -Ei '\\b(vfat|fat|ntfs|exfat)\\b' | grep -v '##OPT##' || true
  register: ##VNAME##_bad
  changed_when: false
  tags: [validate]

- name: ##SID## | record removable media ##OPT## status
  set_fact:
    supp_facts: "{{ supp_facts | combine({
      '##SID##': {
        'status':
          'not_applicable' if not (##VNAME##_all.stdout | trim)
          else ('not_a_finding' if not (##VNAME##_bad.stdout | trim) else 'open'),
        'finding_details':
          'Removable media fstab entries: '
          ~ (##VNAME##_all.stdout | trim if ##VNAME##_all.stdout | trim else '(none - not applicable)')
          ~ '\\nEntries missing ##OPT##: '
          ~ (##VNAME##_bad.stdout | trim if ##VNAME##_bad.stdout | trim else '(none)')
          ~ '\\nResult: '
          ~ ('not_applicable - no removable media entries in fstab'
             if not (##VNAME##_all.stdout | trim)
             else ('not_a_finding - all removable media entries have ##OPT##'
                   if not (##VNAME##_bad.stdout | trim)
                   else 'OPEN - one or more removable media entries missing ##OPT##')),
        'comments': 'Add ##OPT## to all removable media (vfat/ntfs) entries in /etc/fstab.'
      }
    }) }}"
  tags: [validate]
"""

BOOT_EFI_OPT_TMPL = """\

# Checks that /boot/efi is mounted with the ##OPT## option.
# Not applicable on BIOS systems (detected via /sys/firmware/efi).

- name: ##SID## | check for UEFI firmware
  stat:
    path: /sys/firmware/efi
  register: ##VNAME##_efi
  tags: [validate]

- name: ##SID## | get /boot/efi mount options (UEFI only)
  shell: awk '$2 == "/boot/efi" { print $4 }' /proc/mounts
  register: ##VNAME##_opts
  changed_when: false
  when: ##VNAME##_efi.stat.exists
  tags: [validate]

- name: ##SID## | record /boot/efi ##OPT## status
  set_fact:
    supp_facts: "{{ supp_facts | combine({
      '##SID##': {
        'status':
          'not_applicable' if not ##VNAME##_efi.stat.exists
          else ('not_a_finding'
                if '##OPT##' in (##VNAME##_opts.stdout | default(''))
                else 'open'),
        'finding_details':
          'UEFI system: ' ~ (##VNAME##_efi.stat.exists | string | lower)
          ~ '\\n/boot/efi mount options: '
          ~ (##VNAME##_opts.stdout | default('') | trim
             if ##VNAME##_opts.stdout | default('') | trim else '(not mounted or N/A)')
          ~ '\\nResult: '
          ~ ('not_applicable - BIOS system, /boot/efi not applicable'
             if not ##VNAME##_efi.stat.exists
             else ('not_a_finding - ##OPT## is set on /boot/efi'
                   if '##OPT##' in (##VNAME##_opts.stdout | default(''))
                   else 'OPEN - ##OPT## not found in /boot/efi mount options')),
        'comments': 'Add ##OPT## to the /boot/efi entry in /etc/fstab and remount.'
      }
    }) }}"
  tags: [validate]
"""

ENCRYPTION_TMPL = """\

# Checks that persistent filesystems (excluding /boot, /boot/efi) are on LUKS-encrypted
# block devices. N/A if rhel9_attest_disk_encryption_na is true (hypervisor/storage
# provides encryption per documented organizational approval).

- name: ##SID## | check for LUKS crypt block devices
  shell: lsblk -o TYPE | grep -c crypt || true
  register: ##VNAME##
  changed_when: false
  tags: [validate]

- name: ##SID## | record disk encryption status
  set_fact:
    supp_facts: "{{ supp_facts | combine({
      '##SID##': {
        'status':
          'not_applicable' if rhel9_attest_disk_encryption_na | bool
          else ('not_a_finding'
                if (##VNAME##.stdout | trim | int) > 0
                else 'open'),
        'finding_details':
          'Attestation N/A (rhel9_attest_disk_encryption_na): '
          ~ (rhel9_attest_disk_encryption_na | bool | string | lower)
          ~ '\\nLUKS crypt block devices found: ' ~ (##VNAME##.stdout | trim)
          ~ '\\nResult: '
          ~ ('not_applicable - encryption provided at hypervisor or storage layer per org approval'
             if rhel9_attest_disk_encryption_na | bool
             else ('not_a_finding - LUKS crypt block device(s) present'
                   if (##VNAME##.stdout | trim | int) > 0
                   else 'OPEN - no LUKS crypt block devices detected')),
        'comments':
          'Set rhel9_attest_disk_encryption_na: true in group_vars/all/stig_controls.yml '
          ~ 'if encryption is provided by a hypervisor or storage array per org approval. '
          ~ 'Otherwise configure LUKS full-disk encryption at installation time.'
      }
    }) }}"
  tags: [validate]
"""

NODEV_NONROOT_TMPL = """\

# Checks that all non-root local disk partitions are mounted with nodev.
# Root (/) is excluded: mount output format ensures /dev/x on /WORD matches
# only non-root mounts (root mount point ends with a space, not a word char).

- name: ##SID## | check non-root local partitions for missing nodev
  shell: mount | grep '^/dev\\S* on /\\S' | grep --invert-match nodev || true
  register: ##VNAME##
  changed_when: false
  tags: [validate]

- name: ##SID## | record nodev non-root partition status
  set_fact:
    supp_facts: "{{ supp_facts | combine({
      '##SID##': {
        'status': 'not_a_finding' if not (##VNAME##.stdout | trim) else 'open',
        'finding_details':
          'Non-root local mounts missing nodev: '
          ~ (##VNAME##.stdout | trim if ##VNAME##.stdout | trim else '(none)')
          ~ '\\nResult: '
          ~ ('not_a_finding - all non-root local partitions have nodev'
             if not (##VNAME##.stdout | trim)
             else 'OPEN - one or more non-root local partitions missing nodev'),
        'comments': 'Add nodev to affected entries in /etc/fstab and remount.'
      }
    }) }}"
  tags: [validate]
"""


# ─── generators ──────────────────────────────────────────────────────────────

def gen_separate_fs(sid, mountpoint):
    return rule_header(sid) + subst(SEPARATE_FS_TMPL,
        SID=sid, MP=mountpoint, VNAME=vname(sid))

def gen_mount_opt(sid, mountpoint, option):
    return rule_header(sid) + subst(MOUNT_OPT_TMPL,
        SID=sid, MP=mountpoint, OPT=option, VNAME=vname(sid))

def gen_autofs(sid):
    return rule_header(sid) + subst(AUTOFS_TMPL,
        SID=sid, VNAME=vname(sid))

def gen_nfs_opt(sid, option):
    return rule_header(sid) + subst(NFS_OPT_TMPL,
        SID=sid, OPT=option, VNAME=vname(sid))

def gen_removable_opt(sid, option):
    return rule_header(sid) + subst(REMOVABLE_OPT_TMPL,
        SID=sid, OPT=option, VNAME=vname(sid))

def gen_boot_efi_opt(sid, option):
    return rule_header(sid) + subst(BOOT_EFI_OPT_TMPL,
        SID=sid, OPT=option, VNAME=vname(sid))

def gen_encryption(sid):
    return rule_header(sid) + subst(ENCRYPTION_TMPL,
        SID=sid, VNAME=vname(sid))

def gen_nodev_nonroot(sid):
    return rule_header(sid) + subst(NODEV_NONROOT_TMPL,
        SID=sid, VNAME=vname(sid))


# ─── main ────────────────────────────────────────────────────────────────────

def main():
    print("Generating RHEL-09-231xxx supplement task files...")
    generated = []

    for sid, params in sorted(RULE_PARAMS.items()):
        check_type = params[0]
        if check_type == 'separate_fs':
            content = gen_separate_fs(sid, params[1])
        elif check_type == 'mount_opt':
            content = gen_mount_opt(sid, params[1], params[2])
        elif check_type == 'autofs':
            content = gen_autofs(sid)
        elif check_type == 'nfs_opt':
            content = gen_nfs_opt(sid, params[1])
        elif check_type == 'removable_opt':
            content = gen_removable_opt(sid, params[1])
        elif check_type == 'boot_efi_opt':
            content = gen_boot_efi_opt(sid, params[1])
        elif check_type == 'encryption':
            content = gen_encryption(sid)
        elif check_type == 'nodev_nonroot':
            content = gen_nodev_nonroot(sid)
        else:
            print(f'  UNKNOWN type {check_type} for {sid}')
            continue

        write_file(sid, content)
        generated.append(sid)

    print(f"\nGenerated {len(generated)} task files.")
    print("\nAdd to supplement/tasks/main.yml (after last existing import_tasks):")
    for sid in generated:
        print(f"\n- import_tasks: {sid}.yml")
        print(f"  tags: [{sid}]")
        print(f"  when: supp_rules['{sid}'] | default(true) | bool")


if __name__ == '__main__':
    main()
