# Security Policy for GoogleAdminPasswordControl

## Reporting a Vulnerability
To report a security issue, email **security@emayer7139.dev** with:
- **Description:** Impact, affected components  
- **Reproduction steps:** How to trigger the issue  
- **Proof-of-concept:** Example exploit or logs (if available)  
- **Affected versions:** Commit SHA, branch, or release tag  
- **Mitigations:** Any workarounds you’ve identified  

> **Do not** file issues or PRs for vulnerabilities; use this private channel to coordinate securely.

---

## Response Process
1. **Acknowledgment (within 48 hrs):** We’ll confirm receipt and assign a tracking ID.  
2. **Confirmation (within 5 business days):** We’ll reproduce and assess severity.  
3. **Remediation (target: ≤30 days):** Critical fixes prioritized; all supported versions patched.  
4. **Updates:** You’ll receive email status updates at each milestone.

---

## Disclosure Policy
- We practice **coordinated disclosure**:
  1. Patch the default branch (`main`) and previous minor release.  
  2. Publish a GitHub Security Advisory and notify you.  
  3. Publicly disclose once fixes are available.

---

## Scope
Applies to:
- **Default branch** (`main`) and all **tagged releases**  
- Infrastructure-as-code (Terraform, Dockerfiles)  
- Supported versions as defined in our release matrix

---

## Security Controls
- **Branch Protection:** PR reviews, required status checks, and signed commits on `main`.  
- **Code Scanning:** GitHub Advanced Security with Trivy (container) and CodeQL (code).  
- **Secret Scanning:** GitHub push protection to block leaked credentials.  
- **Dependabot:** Automated dependency updates and vulnerability alerts.  
- **Workflow Permissions:** Least-privilege tokens; actions pinned to known good versions.

---

Thank you for helping us keep **GoogleAdminPasswordControl** secure.  
