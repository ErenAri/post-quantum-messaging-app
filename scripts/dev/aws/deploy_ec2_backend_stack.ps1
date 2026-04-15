[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$InstanceHost,
  [Parameter(Mandatory = $true)]
  [string]$KeyFile,
  [string]$SshUser = "ubuntu",
  [string]$RemoteRoot = "/opt/pqmsg",
  [string]$LocalEc2AssetsPath = "deploy/aws/ec2"
)

$ErrorActionPreference = "Stop"

function Invoke-ExternalChecked {
  param(
    [string]$Description,
    [scriptblock]$Action
  )
  Write-Host $Description -ForegroundColor Cyan
  & $Action
  if ($LASTEXITCODE -ne 0) {
    throw "Failed: $Description"
  }
}

if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
  throw "ssh was not found in PATH. Install OpenSSH client first."
}
if (-not (Get-Command scp -ErrorAction SilentlyContinue)) {
  throw "scp was not found in PATH. Install OpenSSH client first."
}

$keyFullPath = (Resolve-Path -Path $KeyFile).Path
$assetsFullPath = (Resolve-Path -Path $LocalEc2AssetsPath).Path
$remote = [string]::Format("{0}@{1}", $SshUser, $InstanceHost)
$colon = [char]58
$owner = $SshUser + $colon + $SshUser
$scpTarget = $remote + $colon + "/tmp/pqmsg-ec2"
$remotePrep = "sudo mkdir -p " + $RemoteRoot + "; sudo chown -R " + $owner + " " + $RemoteRoot + "; mkdir -p /tmp/pqmsg-ec2"

Invoke-ExternalChecked -Description "Creating remote directories" -Action {
  ssh -i $keyFullPath $remote $remotePrep
}

Invoke-ExternalChecked -Description "Copying EC2 deployment assets" -Action {
  scp -i $keyFullPath -r "$assetsFullPath/." $scpTarget
}

$installCmd = "mkdir -p $RemoteRoot/deploy/aws/ec2; cp -r /tmp/pqmsg-ec2/. $RemoteRoot/deploy/aws/ec2/; if [ ! -f $RemoteRoot/deploy/aws/ec2/.env ]; then cp $RemoteRoot/deploy/aws/ec2/.env.example $RemoteRoot/deploy/aws/ec2/.env; fi; if [ ! -f $RemoteRoot/deploy/aws/ec2/pqmsg-server.aws.env ]; then cp $RemoteRoot/deploy/aws/ec2/pqmsg-server.aws.env.example $RemoteRoot/deploy/aws/ec2/pqmsg-server.aws.env; fi; sudo cp $RemoteRoot/deploy/aws/ec2/systemd/pqmsg-backend-compose.service /etc/systemd/system/pqmsg-backend-compose.service; sudo systemctl daemon-reload"

Invoke-ExternalChecked -Description "Installing stack files and systemd unit" -Action {
  ssh -i $keyFullPath $remote $installCmd
}

Write-Host "Remote install complete." -ForegroundColor Green
Write-Host "Next steps on the instance:" -ForegroundColor Yellow
Write-Host "  1) Edit $RemoteRoot/deploy/aws/ec2/.env and set API_DOMAIN, ACME_EMAIL, POSTGRES_PASSWORD."
Write-Host "  2) Edit $RemoteRoot/deploy/aws/ec2/pqmsg-server.aws.env and confirm PQMSG_CORS_ALLOWED_ORIGINS."
Write-Host "  3) Start services: sudo systemctl enable --now pqmsg-backend-compose.service"
Write-Host "  4) Check status: sudo systemctl status pqmsg-backend-compose.service --no-pager"
Write-Host "  5) Tail logs: sudo docker compose --env-file $RemoteRoot/deploy/aws/ec2/.env -f $RemoteRoot/deploy/aws/ec2/docker-compose.ec2.yml logs -f"
