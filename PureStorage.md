# Keymaster in PureStorage

- This is a fork-repository from upstream open-source version https://github.com/Cloud-Foundations/keymaster
- As corporate GH account do not support any interaction with repositories outside of the organization, it is not possible to fork the repository directly. 
  - It has to be manually cloned and pushed to the corporate account (one-time operation). Thanks to this we don't have native fork repo functionality, e.g., commit differences status
  - It is needed to watch for changes manually
- Primary build branch is `main` with custom modifications (e.g., GHA workflows). Upstream master should be periodically reviewed and merged to main.
- Pull request to the upstream should be opened whenever possible, share changes with the upstream. Maintainers are friendly and open to this collaboration. Personal GH account has to be used for that. 

## Upstream Contributing
- You need to create a separate personal GH account. GH supports account switcher, it makes this split-world operation easier
- Create PRs from the personal account to the upstream repository
- Once merged, sync master branches in our fork manually and rebase pure branch on top of it

One way to combine corporate and personal GH accounts is to use SSH with keys registered to both:

`~/.ssh/config`:
```
Host github.com
HostName github.com
User git
IdentityFile ~/.ssh/id_rsa

Host github-personal
HostName github.com
User git
IdentitiesOnly yes
IdentityFile ~/.ssh/id_rsa_github_personal
```

Remotes
```
origin	https://github.com/pure-product-security/keymaster.git (fetch)
origin	https://github.com/pure-product-security/keymaster.git (push)
ph4ssh	git@github-personal:myuser/keymaster.git (fetch)
ph4ssh	git@github-personal:myuser/keymaster.git (push)
cf      git@github-personal:Cloud-Foundations/keymaster.git (fetch)
cf      git@github-personal:Cloud-Foundations/keymaster.git (push)
```

## Building

- Local build is possible via `make`. It is good for testing and development
- Official builds are made via GHA. 
  - GHA publishes artifacts after the build. 

### Default server
Keymaster is built with the following environment variable so the Keymaster server is compiled into the binary.
This enables to run Keymaster without configuration file.

```
VERSION_FLAVOUR=pure DEFAULT_HOST="keymaster.sec.cloud-support.purestorage.com" make install-client
```

- `VERSION_FLAVOUR` is appended to the version to distinguish upstream builds from pure builds\
- `DEFAULT_HOST` is the default Keymaster server address

# GHA Setup
GHA is used to build keymaster client for all used architectures: 
- Linux, runs on pure1build runners, default
- Windows, runs on a self-hosted runner
- OSX, runs on a shared self-hosted runner

## Testing

Yubikey support needs to be tested on all architectures. 
- OSX: typically easy as developers use it
- Linux
  - Install VMWare Fusion via Self Service, Run Ubuntu ISO, connect Yubikey USB to the VM, run `keymaster -checkDevices` and potentially try to login with Yubikey enabled. 
  - If OSX is running on ARM, also Ubuntu image has to be ARM.
  - No installation is needed, live boot works fine
- Windows
  - Use VMWare Fusion, pick download from Microsoft, quickly install it (if done otherwise, network drivers are not available, installation won't progress)
  - run `keymaster -checkDevices`
  - ARM build for Keymaster is not yet working, however, ARM Windows can run x86 binaries 

---------------

## OSX GHA Runner
We use self-hosted GHA Runner installed on a Mac Mini shared with Pure1Mobile team.
Dominik Salai installed the runner, if there is an issue with it, contact him.

- Runner name: `dx-prg-mac-ci-01`
- Runner group: `pure1MacOS` (installed on org-level for `pure-product-security`)
- Tags: self-hosted macOS ARM64

No special configuration is needed, all dependencies are installed

### Code signing

OSX binaries needs to be code-signed.

- Pure1 has a [company account with Apple](https://developer.apple.com/account), Pure1 mobile team is using it primarily, pure1-security-prague was added there. 
  - Each developer has individual Apple ID (with company email)
  - Only those having Admin / Owner access can generate Distribution certificates
    - currently, holder is registered at `mobileapps@purestorage.com`, Tim Noack has access to 2nd factor. Opening a PERC ticket should be enough to get certificates renewed 
  - A new team member should create Apple ID with company email, then ask for access to the Apple account (maybe ask for the invitation first)
- There are 2 [identifiers](https://developer.apple.com/account/resources/identifiers/list) created
  - Keymaster as `com.purestorage.keymaster`
  - Purelogin2 as `com.purestorage.purelogin2`
- Required code-signing certificates; admin/holder has to create it in [Certificates, Identifiers & Profiles](https://developer.apple.com/account/resources/certificates/list) or via XCode
  - `Developer ID Application: Pure Storage Inc. (4PQYP85VSU)` ([notarization requires it](https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/resolving_common_notarization_issues#3087721))
  - `Developer ID Installer: Pure Storage Inc. (4PQYP85VSU)` for creating an installer
  - Install XCode, login with the Apple ID, check Pure Storage Inc. certificates. 
  - If there is no Apple Distribution / Development certificate, create one. It will be stored in the Keychain.
  - For the Developer ID certificates you need to create CSR, e.g., via Keychain Access -> Certificate Assistant -> Request a Certificate from a Certificate Authority 
  - Certificates are issued for 1 year, if it is expired, create a new one
  - Intermediate certificate is typically not imported in the keychain, causing code-signing to fail. It is thus needed to import the intermediate certificate to the System keychain. 
    - Determine Intermediate certificate issuer from the Apple Distribution certificate (it was G3 for the current one) 
    - Download the intermediate certificate from https://www.apple.com/certificateauthority/
    - Import it to the keychain (click it)

The `CSSMERR_TP_NOT_TRUSTED` error means that intermediate certificate needs to be imported to the system KeyChain
```shell
curl -o apple_intermediate.cer https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer
sudo security import apple_intermediate.cer -k /Library/Keychains/System.keychain
```

Code-signing can be tested locally
```shell
# List available identities
security find-identity -p codesigning

# Codesign
codesign --sign "Developer ID Application: Pure Storage Inc. (4PQYP85VSU)" --timestamp --options runtime -v build/purelogin
```

### Notarization

Notarization helps to avoid flagging executable as potentially harmful.

Steps to Create an App-Specific Password
- Log in to Your Apple ID Account:
  - Go to the Apple ID account page at [appleid.apple.com](https://appleid.apple.com/account/manage).
  - Sign in with your Apple ID and password.
- Navigate to the Security Section:
  - Look for the "App-Specific Passwords" section under "Security".
- Generate an App-Specific Password:
  - Click on “Generate Password…”.
  - Enter a label for the password, such as "Notarization" or "CI/CD Deployment", to help you remember the purpose of this password.
  - Apple will generate a password for you. Make sure to copy this password as you will not be able to see it again once you leave or refresh the page.

### GHA Setup

Setup GH variables and secrets:

#### Variables
```
APPLE_BUNDLE_ID: com.purestorage.keymaster
APPLE_DEV_IDENTITY: Developer ID Application: Pure Storage Inc. (4PQYP85VSU)
APPLE_INS_IDENTITY: Developer ID Installer: Pure Storage Inc. (4PQYP85VSU)
APPLE_ID_INTERMEDIATE_CERT_URL: https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer
APPLE_TEAM_ID: 4PQYP85VSU
APPLE_ID: yourappleid@purestorage.com
OSX_RUNS_ON: p1sp
```

#### Secrets
Export the signing certificate and private key (select both in the Keychain), right click, export to p12, set a random strong password.

In order to protect signing secrets from an exposure, we use environment secrets.
- Go to [repository environments](https://github.com/pure-product-security/keymaster/settings/environments), add `production`
- Setup protection so only main branch can use this environment
- Add following environment secrets:

```shell
APPLE_DEV_P12_BASE64: base64 -i apple-developer-id-app.p12
APPLE_DEV_PASSWORD: "password"

APPLE_INS_P12_BASE64: base64 -i apple-developer-id-ins.p12
APPLE_INS_PASSWORD: "password"

APPLE_APP_SPECIFIC_PASSWORD: "password"
```

### Manual import and verification

```shell
security create-keychain -p "" build.keychain
security unlock-keychain -p "" build.keychain
security set-keychain-settings -t 3600 -u build.keychain
security list-keychains -d user -s build.keychain

sudo security import apple_intermediate.cer -k /Library/Keychains/System.keychain
security import /tmp/apple_intermediate.cer -k build.keychain
security import /tmp/certificate.p12 -k build.keychain -P "${{ secrets.APPLE_DIST_PASSWORD }}" -T "/usr/bin/codesign" -T /usr/bin/productsign
security set-key-partition-list -S apple-tool:,apple: -s -k "" build.keychain

security find-certificate -a -Z build.keychain
security find-certificate -a -p build.keychain > allcerts.pem
(openssl crl2pkcs7 -nocrl -certfile allcerts.pem | openssl pkcs7 -print_certs -noout) || true

security find-certificate -c "${{ vars.APPLE_DIST_IDENTITY }}" -p build.keychain > mycert.pem
openssl x509 -in mycert.pem -text -noout
security verify-cert -v -k build.keychain -c mycert.pem || true
security verify-cert -v -k build.keychain -c mycert.pem -p codeSign || true

security find-identity -p codesigning build.keychain
security find-identity -p codesigning
security find-identity build.keychain
security find-identity
```

### GHA Runner installation
- Create a dedicated host p1sp-mac
  - https://us-west-2.console.aws.amazon.com/ec2/home?region=us-west-2#Host:hostId=h-020d73b7c5ec7d177
  - instance family mac2 (m1, the cheapest one), mac2.metal
  - Billed first 24 hours, when allocated, paying for it. Need to release it to stop billing
- Create a new instance ps1p-mac
  - https://us-west-2.console.aws.amazon.com/ec2/home?region=us-west-2#InstanceDetails:instanceId=i-029a9e493fc08c991
  - mac2.metal
  - Setup Instance role `ec2-p1sp-osx`
  - It has to be in the same subnet as a dedicated host
  - connect: `ssh -i ~/.ssh/p1sp-infra.pem ec2-user@10.134.19.43`
- Resources:
  - https://aws.amazon.com/ec2/dedicated-hosts/getting-started/
  - https://aws.amazon.com/ec2/dedicated-hosts/pricing/
  - https://calculator.aws/#/createCalculator/ec2-enhancement
  - https://aws.amazon.com/ec2/instance-types/mac/

#### EC2 role for the runner

Runner has created [IAM Role](https://us-east-1.console.aws.amazon.com/iam/home?region=us-west-2#/roles) `ec2-p1sp-osx`
with the following policies attached:
```
AmazonSSMManagedEC2InstanceDefaultPolicy
AmazonSSMManagedInstanceCore
AmazonEC2ReadOnlyAccess
```

#### Machine setup
- https://www.scaleway.com/en/docs/tutorials/install-github-actions-runner-mac/
- https://repost.aws/knowledge-center/ec2-mac-instance-gui-access
- XCode has to be installed via VNC

```shell
# install xcode tools
xcode-select --install

# install roseta
softwareupdate --install-rosetta

# install brew
CI=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# install tools
brew install nmap vim rsync git golang python

# install java
brew install openjdk@17 && brew link --force --overwrite openjdk@17
echo 'export PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH"' >> ~/.zshrc

# install intermediate cert
curl -o apple_intermediate.cer https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer
sudo security import apple_intermediate.cer -k /Library/Keychains/System.keychain

# Enable VNC (for XCode installation)
sudo defaults write /var/db/launchd.db/com.apple.launchd/overrides.plist com.apple.screensharing -dict Disabled -bool false
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.screensharing.plist

# Set ec2-user passwd
sudo /usr/bin/dscl . -passwd /Users/ec2-user

# vnc tunnel: ssh -i keypair_file -L 5900:localhost:5900 ec2-user@192.0.2.0
# vnc access: vnc://localhost:5900
```

Install the XCode, open it, install MacOS SDK, agree with the license.

#### SSH config
```shell
Host p1sp-mac
  HostName 10.134.19.43
  User ec2-user
  IdentityFile ~/.ssh/p1sp-infra.pem
  LocalForward 5900 localhost:5900
```

#### Runner installation

Create a new user
```shell
sudo sysadminctl -addUser gha -fullName "GHA runner" -password "password"
```

Follow the process from self-runner page, then
```shell
./config.sh --url https://github.com/pure-product-security --token TOKEN_HERE --runnergroup pure1MacOS --labels 'p1sp' --name p1sp-mac-metal-infra
```

edit `/Users/gha/actions-runner/.env`:
```shell
ImageOS=macos14
XCODE_15_DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
```

Install it as a service
```shell
/Users/gha/actions-runner/svc.sh install
/Users/gha/actions-runner/svc.sh start
```

Or:
```shell
sudo vim /Library/LaunchDaemons/com.github.actions.runner.plist
```

Contents
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.github.actions.runner</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/gha/actions-runner/runsvc.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>/Users/gha/actions-runner</string>  
    <key>StandardErrorPath</key>
    <string>/Users/gha/actions-runner/logs/err.log</string>
    <key>StandardOutPath</key>
    <string>/Users/gha/actions-runner/logs/out.log</string>
    <key>UserName</key>
    <string>gha</string>
    <key>EnvironmentVariables</key>
    <dict>
      <key>ACTIONS_RUNNER_SVC</key>
      <string>1</string>
    </dict>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>SessionCreate</key>
    <true/>
</dict>
</plist>
```

Then
```shell
sudo chown root:wheel /Library/LaunchDaemons/com.github.actions.runner.plist
sudo chmod 644 /Library/LaunchDaemons/com.github.actions.runner.plist

# Load the service 
sudo launchctl load -w /Library/LaunchDaemons/com.github.actions.runner.plist

# Start the service
sudo launchctl start com.github.actions.runner

# Verify
sudo launchctl list | grep com.github.actions.runner
```

--------------- 

## Windows GHA runner

- A Windows 2022 Server is started in EC2 Infra account, [i-015af7e28040f70be](https://us-west-2.console.aws.amazon.com/ec2/home?region=us-west-2#InstanceDetails:instanceId=i-015af7e28040f70be) named `p1sp-win2022`
- It has RDP and SSH server running. SSH drops to powershell
- There is an alias for mingw64 bash: `bash`

### EC2 role for the runner

Runner has created [IAM Role](https://us-east-1.console.aws.amazon.com/iam/home?region=us-west-2#/roles) `ec2-p1sp-windows`
with the following policies attached:
```
AmazonSSMManagedEC2InstanceDefaultPolicy
AmazonSSMManagedInstanceCore
AmazonEC2ReadOnlyAccess
```

### Immediate setup after install

```shell
# Enable admin
net user administrator /active:yes

# Enable RDP (Remote Desktop Service)
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Check if RDP is running
Get-Service -Name TermService | Select-Object Status, Name, DisplayName
```

### Dependencies

Install all following dependencies

- https://go.dev/doc/install
- https://www.oracle.com/java/technologies/downloads/#jdk21-windows
- https://gitforwindows.org/
- https://github.com/git-for-windows/build-extra/releases/tag/git-sdk-1.0.8
  - Do not enable experimental Git features, it breaks GHA Runner checkout 
- https://nsis.sourceforge.io/Download (Windows installer builder)
  - https://github.com/GsNSIS/EnVar/releases/tag/v0.3.1, extract to NSIS
  - Another source (possibly older) https://nsis.sourceforge.io/mediawiki/images/7/7f/EnVar_plugin.zip 
- https://slproweb.com/products/Win32OpenSSL.html
- https://www.python.org/ftp/python/3.12.3/python-3.12.3-amd64.exe, Install to `/c/Python312/python`
- Make sure that system path contains:

```shell
C:\Program Files\Common Files\Oracle\Java\javapath
C:\git-sdk-64
C:\Program Files\Git\cmd
C:\Program Files\Go\bin
C:\Program Files (x86)\NSIS\Bin
```

### Create users

- Create a new users "ubuntu" (for normal work via SSH / RDP) and "gha" (will run GHA runner)
- Settings -> System -> Remote Desktop -> Select users that can remotely access this PC

```powershell
New-LocalUser -Name "ubuntu" -Description "SSH User Account"
Set-LocalUser -Name "ubuntu" -Password (ConvertTo-SecureString -AsPlainText "YourSecurePassword" -Force)

$userDir = "C:\Users\ubuntu"
$sshDir = "$userDir\.ssh"
New-Item -ItemType Directory -Path $sshDir -Force
$authKeysFile = "$sshDir\authorized_keys"
New-Item -ItemType File -Path $authKeysFile -Force

icacls $sshDir /inheritance:r /grant "ubuntu:(OI)(CI)F" /grant "SYSTEM:(OI)(CI)F"
icacls $authKeysFile /inheritance:r /grant "ubuntu:R" /grant "SYSTEM:R"
```

### Setup SSH sever
https://www.server-world.info/en/note?os=Windows_Server_2022&p=ssh&f=1

```shell
Start-Service -Name "sshd"
Set-Service -Name "sshd" -StartupType Automatic
Get-Service -Name "sshd" | Select-Object *
New-NetFirewallRule -Name "SSH" `
-DisplayName "SSH" `
-Description "Allow SSH" `
-Profile Any `
-Direction Inbound `
-Action Allow `
-Protocol TCP `
-Program Any `
-LocalAddress Any `
-RemoteAddress Any `
-LocalPort 22 `
-RemotePort Any

# Powershell by default
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" `
                 -Name DefaultShell `
                 -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
                 -PropertyType String `
                 -Force

# install git sdk: https://github.com/git-for-windows/build-extra/releases/tag/git-sdk-1.0.8
New-Alias -Name git-bash -Value "C:\git-sdk-64\git-bash.exe"

# Restart sshd
Restart-Service sshd
```

#### Create an aliases
```shell
# over ssh
echo $PROFILE
```

Edit `C:\Users\ubuntu\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`
```powershell
function Open-BashMingw64 {
    param(
        [Parameter(ValueFromRemainingArguments=$true)]
        [string[]]$args
    )
    & 'C:\git-sdk-64\msys2_shell.cmd' -mingw64 -no-start -here -defterm @args
}
New-Alias -Name git-bash2 -Value Open-GitBash2
New-Alias -Name bash -Value Open-BashMingw64
New-Alias -Name bash-mingw64 -Value Open-BashMingw64
New-Alias -Name rsync -Value "C:\git-sdk-64\usr\bin\rsync.exe"
New-Alias -name makensis -Value "C:\Program Files (x86)\NSIS\Bin\makensis.exe"
```

#### Authorized SSH Keys - Administrator
```shell
$userDir = "C:\Users\Administrator"
Set-Location $userDir

$sshDir = "$userDir\.ssh"
if (-Not (Test-Path $sshDir)) {
    New-Item -ItemType Directory -Path $sshDir
}

$authKeysFile = "$sshDir\authorized_keys"
if (-Not (Test-Path $authKeysFile)) {
    New-Item -ItemType File -Path $authKeysFile
}

# create the file
notepad $authKeysFile

# Set permissions for the .ssh directory
icacls $sshDir /inheritance:r /grant "Administrator:F" /grant "SYSTEM:F"

# Set permissions for the authorized_keys file
icacls $authKeysFile /inheritance:r /grant "Administrator:R" /grant "SYSTEM:R"

# ssh-agent
Start-Service ssh-agent
Set-Service -Name "ssh-agent" -StartupType Automatic

# enable PubkeyAuthentication yes
notepad 'C:\ProgramData\ssh\sshd_config'

# create admin auth keys
/c/ProgramData/ssh/administrators_authorized_keys
icacls.exe "C:\ProgramData\ssh\administrators_authorized_keys" /inheritance:r /grant "*S-1-5-32-544:F" /grant "SYSTEM:F"
```

### Enable WSL
Note that WSL2 is supported only on bare-metal Windows installations, virtualized EC2s support only WSL1.
https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/install-wsl-on-ec2-windows-instance.html

```shell
# Enable WSL
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart

# Enable Virtual Machine Platform
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart

# EC2 non-metal requires v1
wsl --set-default-version 1

# Will reboot (needed)
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux

# Install
wsl --list -o
wsl --install -d Ubuntu

# If that does not work:
Invoke-WebRequest -Uri https://aka.ms/wslubuntu2204 -OutFile "C:\Users\Administrator\Downloads\ubuntu2204.appx" -UseBasicParsing

# Download https://learn.microsoft.com/en-us/troubleshoot/developer/visualstudio/cpp/libraries/c-runtime-packages-desktop-bridge#how-to-install-and-update-desktop-framework-packages
Add-AppxPackage .\Microsoft.VCLibs.x64.14.00.Desktop.appx
Add-AppxPackage .\Ubuntu_2204.1.7.0_x64.appx
Add-AppxPackage -Path "C:\Users\Administrator\Downloads\ubuntu2204.appx"
```

### Installing GHA runner

- https://github.com/pure-product-security/purelogin2/settings/actions/runners/new?arch=x64&os=win
- runner group name pure1Windows
- add org-level runner, ask DXEP to send you install self-hosted runner commands (contains the token)

Runner help
```
 --unattended           Disable interactive prompts for missing arguments. Defaults will be used for missing options
 --url string           Repository to add the runner to. Required if unattended
 --token string         Registration token. Required if unattended
 --name string          Name of the runner to configure (default EC2AMAZ-DVPMET0)
 --runnergroup string   Name of the runner group to add this runner to (defaults to the default runner group)
 --labels string        Custom labels that will be added to the runner. This option is mandatory if --no-default-labels is used.
 --no-default-labels    Disables adding the default labels: 'self-hosted,Windows,X64'
 --local                Removes the runner config files from your local machine. Used as an option to the remove command
 --work string          Relative runner work directory (default _work)
 --replace              Replace any existing runner with the same name (default false)
 --pat                  GitHub personal access token with repo scope. Used for checking network connectivity when executing `.\run.cmd --check`
 --disableupdate        Disable self-hosted runner automatic update to the latest released version`
 --ephemeral            Configure the runner to only take one job and then let the service un-configure the runner after the job finishes (default false)
 --runasservice   Run the runner as a service
 --windowslogonaccount string   Account to run the service as. Requires runasservice
 --windowslogonpassword string  Password for the service account. Requires runasservice
```

Runner Installation
```
./config.cmd --url https://github.com/pure-product-security --token TOKEN_FROM_RUNNER_SETUP_PAGE_ON_GITHUB --runasservice --windowslogonaccount ".\gha" --windowslogonpassword "GHAUSERPASSWORD" --runnergroup pure1Windows --labels 'p1sp,windows2022' --name p1sp-win2022-dvpmet0

This runner will have the following labels: 'self-hosted', 'Windows', 'X64'
Enter any additional labels (ex. label-1,label-2): [press Enter to skip] p1sp,windows2022

git config --system core.usebuiltinfsmonitor false
```


#### Manual FHA service installation (not recommended)
Install service - sucks, do it as above
- Open Local Security Policy:
    - Type `secpol.msc` in the Start menu and open it.
- Navigate to User Rights Assignment:
    - Go to Security Settings → Local Policies → User Rights Assignment.
- Modify "Log on as a service":
    - Find the "Log on as a service" policy.
    - Add the user account you wish to use for the service.
```
sc.exe create "GHARunner2" binPath= "C:\actions-runner\run-helper.cmd" DisplayName= "GHA Runner" start= auto obj= "EC2AMAZ-DVPMET0\gha" password= "GHAUSERPASSWORD"
sc.exe failure "GHARunner2" reset= 86400 actions= restart/5000
Set-Service -Name "GHARunner2" -StartupType Automatic
Start-Service -Name "GHARunner2"

Get-Service -Name "GHARunner2" | Select-Object Status, Name, DisplayName
Get-WmiObject Win32_Service | Where-Object {$_.Name -eq "GHARunner"} | Select-Object Name, StartName
```
