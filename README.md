# nvrules2re

**nvrules2re** is a CLI tool that converts [NeuVector](https://open-docs.neuvector.com/policy/processrules) Process Profile Rules into [Runtime Enforcer](https://github.com/rancher-sandbox/runtime-enforcer).

This tool simplifies the migration from NeuVector's Process Profile rules to [Runtime Enforcer](https://github.com/rancher-sandbox/runtime-enforcer) — a universal policy engine for Kubernetes that streamlines the adoption of policy-as-code practices.

## Features

- Parse NeuVector process profile rules (exported via `/v1/file/group` API)
- Generate equivalent Runtime Enforcer `WorkloadPolicy` resources with NV group name as its resource name
- Supports output to stdout or to a file
- Optionally enable monitor/protect mode
- Display a summary showing the status of each rule conversion

## System Requirements

### Runtime Requirements

- **Kubernetes cluster connection**: Runtime Enforcer is capable of specifying different rules for different container, but it requires the target container name in the WorkloadPolicy.  This information is not included in NV process profile rules.  You'd require a kubernetes cluster connection in order for **`nvrules2re`** to retrieve the container name for you.
- **Supported platforms**: Linux, macOS, Windows


### Build Requirements

If you're building from source, you'll need:

- **Go**: See go.mod for the specific version requirement.
- **Make**: For building using the provided Makefile


## Quick Start

This guide provides step-by-step instructions to set up and execute **`nvrules2re`**, help you convert NeuVector Process Profile Rules into Runtime Enforcer WorkloadPolicies within your environment.

---

### 🛠️ Installation

You can either:

* Download the latest release binary from the [Releases](https://github.com/holyspectral/neuvector-runtime-enforcer-policy-converter/releases) page, or
* Build from source:
```bash
make
```

---

### 📥 Fetch NeuVector Process Profile Rules

You will get `rules.yaml`

#### Option 1: REST API

```bash
curl "https://<API_SERVER_ADDRESS>/v1/file/group" \
-H "Content-Type: application/json" \
-H "X-Auth-Apikey: <API_KEY>" \
--data-raw '{"groups":["<group name>"]}' \
-o rules.yaml.gz
gunzip rules.yaml.gz
```

#### Option 2: Console UI

1. Navigate to **Policy → Groups**
2. Select the group policy that you want to export
3. Click Export Group Policy
4. Ignore the Process Policy mode.  You will be given the option to override it in the **`nvrules2re`** later.
5. Leave `Use Name Referral` unchecked, select `Download to Local` and click `Submit`
6. You will download a file like `cfgGroupsExport_20260626105448.yaml` that you can use later.

---

### 🔄 Convert to Runtime Enforcer WorkloadPolicy CR

#### CLI Usage

NOTE: You will need kubernetes cluster access in order to run the CLI.

```bash
nvrules2re convert <yaml_file>
```

**Examples:**
```bash
# Convert rules from a YAML file (output defaults to stdout)
nvrules2re convert rules.yaml

# Specify custom output file
nvrules2re convert rules.yaml --output my-policies.yaml

# Override all rules to monitor mode
nvrules2re convert rules.yaml --mode monitor
```
---

### 🔄 Assign WorkloadPolicy to workload

To assign Runtime Enforcer WorkloadPolicy to a workload, you have to add a label in your workload.

NOTE: WorkloadPolicy is namespace-scoped.  You'd need to match the WorkloadPolicy's namespace with your workload.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ubuntu-deployment
  labels:
    app: ubuntu
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ubuntu
  template:
    metadata:
      labels:
        app: ubuntu
        security.rancher.io/policy: workloadpolicy-sample # replace with the WorkloadPolicy name.
    spec:
      containers:
      - name: ubuntu
        image: ubuntu
```

---

### ⚙️ Mode Resolution

Instead of relying on the mode defined in NV process rules, the effective enforcement mode in Runtime Enforcer WorkloadPolicy will always be the one specified by **`nvrules2re`**.  This is because Runtime Enforcer uses a different kernel hook.  We recommend running in monitor mode first before converting it to protect mode to prevent false positives and service interruption.

---

### 🔍 CLI Usage Overview

```
NAME:
   nvrules2re - Convert NeuVector Process Profile rules to Runtime Enforcer WorkloadPolicy

USAGE:
   nvrules2re [global options] [command [command options]]

COMMANDS:
   convert  Convert NvSecurityRule YAML files to WorkloadPolicy YAML
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h  show help
```

---
## Note
- **Avoid double enforcement.** After converting NeuVector process rules to Runtime Enforcer WorkloadPolicy, disable the matching NeuVector rules.
