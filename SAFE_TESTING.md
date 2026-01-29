# Safe Malware Testing Guidelines 🔒

This document explains how to safely test malware samples against the code in this repository. **Do not run untrusted malware on your regular workstation or on runners with network access.**

Recommendations:

- Use an isolated virtual machine or dedicated hardware with networking disabled and snapshots enabled. Example tools: QEMU/KVM, VMware, VirtualBox.
- Use disposable ephemeral VMs: snapshot, restore for each sample, and destroy afterwards.
- Disable host–guest file sharing and mount only the files required for the test.
- Keep monitoring tools active from the host side only; do not allow the guest to access your network or cloud credentials.
- For CI: use dedicated self-hosted, air-gapped runners with no network and no persistent storage, or run tests only on 'main' branch with restricted access.
- Prefer static and dynamic analysis in a sandbox (static parsing, sanitizers, fuzzing) before executing any sample.

If you want me to run samples here, you must either:
1. Upload the sample(s) into this repository under `tests/samples/` explicitly (recommended), or
2. Provide a precise, trusted URL and explicit permission for me to download it into this workspace.

If you provide samples, I will only run them in an air-gapped sandbox or provide instructions to run them locally in your secure environment. If you'd like, I can also provide a VM image and step-by-step instructions for a safe test environment.
