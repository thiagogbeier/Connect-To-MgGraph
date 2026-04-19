# Connect-To-MgGraph

PowerShell helper to connect to Microsoft Graph with multiple authentication modes, including unattended automation-friendly options.

## Install

```powershell
Install-Script -Name Connect-ToMgGraph
```

## Why this project

This script is designed for automation scenarios where human interaction should be optional or avoided, such as:

- Jenkins pipelines
- Azure Automation runbooks
- Azure DevOps pipelines
- Ansible playbooks

## Authentication modes

The script supports authentication patterns documented for `Connect-MgGraph`.

### Delegated auth (interactive)

```powershell
.\Connect-ToMgGraph.ps1 -interactive
```

### Delegated auth (device code)

```powershell
.\Connect-ToMgGraph.ps1 -devicecode
```

### Delegated auth (scopes only)

```powershell
.\Connect-ToMgGraph.ps1 -scopesonly
```

### App-only auth (client secret)

```powershell
.\Connect-ToMgGraph.ps1 -entraapp -AppId "<app-id>" -AppSecret "<app-secret>" -TenantId "<tenant-id>"
```

### App-only auth (certificate thumbprint)

```powershell
.\Connect-ToMgGraph.ps1 -usessl -AppId "<app-id>" -TenantId "<tenant-id>" -CertificateThumbprint "<thumbprint>"
```

### App-only auth (certificate subject name)

```powershell
.\Connect-ToMgGraph.ps1 -usessl -AppId "<app-id>" -TenantId "<tenant-id>" -CertificateName "CN=GraphAutomationCert"
```

### Managed identity (system-assigned)

```powershell
.\Connect-ToMgGraph.ps1 -managedidentity
```

### Managed identity (user-assigned)

```powershell
.\Connect-ToMgGraph.ps1 -managedidentity -ManagedIdentityClientId "<managed-identity-client-id>"
```

### Environment variable-based auth

```powershell
.\Connect-ToMgGraph.ps1 -environmentvariable
```

### Existing access token

```powershell
.\Connect-ToMgGraph.ps1 -accesstokenauth -AccessToken "<jwt-access-token>"
```

## Cloud environment selection

Use `-Environment` with one of:

- `Global` (default)
- `USGov`
- `USGovDoD`
- `China`

Example:

```powershell
.\Connect-ToMgGraph.ps1 -managedidentity -Environment USGov
```

## Session helpers

```powershell
.\Connect-ToMgGraph.ps1 -status
.\Connect-ToMgGraph.ps1 -disconnects
.\Connect-ToMgGraph.ps1 -disconnects -SkipConfirmation
```

## Notes for automation

- Prefer `-managedidentity`, `-entraapp`, or `-usessl` for non-interactive automation.
- Use secret stores (Azure Key Vault, Jenkins credentials, Azure DevOps secret variables, Ansible Vault) and avoid plain text secrets in source control.
- Use one authentication mode per invocation.

## GitHub Actions publishing

This repository includes a GitHub Actions workflow to publish to PowerShell Gallery when version is bumped after a full update.

Workflow file:

- `.github/workflows/publish-psgallery.yml`

Required repository secret:

- `PSGALLERY_API_KEY` (PowerShell Gallery API key with publish permission)

Release flow:

1. Update code.
2. Bump version in both places:
   - `Connect-ToMgGraph.ps1` -> `.VERSION`
   - `Connect-ToMgGraph.psd1` -> `ModuleVersion`
3. Merge to `main`.
4. Workflow validates version consistency, checks duplicate versions in PSGallery, and publishes with `Publish-Script`.
5. If publish succeeds from a branch push, workflow creates a matching tag like `v1.3.1`.

Optional tag path:

- Pushing a tag that matches `v*.*.*` also triggers the same workflow.
- Tag version must match script/manifest version.
