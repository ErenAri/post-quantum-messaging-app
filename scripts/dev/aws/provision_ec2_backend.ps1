[CmdletBinding()]
param(
  [string]$Region = "us-east-1",
  [string]$NamePrefix = "pqmsg",
  [string]$InstanceType = "t2.micro",
  [Parameter(Mandatory = $true)]
  [string]$KeyName,
  [string]$VpcId,
  [string]$SubnetId,
  [string]$SecurityGroupId,
  [string]$AmiId,
  [string]$SshIngressCidr
)

$ErrorActionPreference = "Stop"

function Invoke-AwsJson {
  param([string[]]$AwsArgs)
  $output = & aws @AwsArgs
  if ($LASTEXITCODE -ne 0) {
    throw "AWS CLI command failed: aws $($AwsArgs -join ' ')"
  }
  if (-not $output) {
    return $null
  }
  return $output | ConvertFrom-Json
}

function Invoke-AwsText {
  param([string[]]$AwsArgs)
  $output = & aws @AwsArgs
  if ($LASTEXITCODE -ne 0) {
    throw "AWS CLI command failed: aws $($AwsArgs -join ' ')"
  }
  return ($output | Out-String).Trim()
}

function Add-IngressRule {
  param(
    [string]$Region,
    [string]$GroupId,
    [string]$Protocol,
    [int]$FromPort,
    [int]$ToPort,
    [string]$Cidr
  )
  $result = & aws ec2 authorize-security-group-ingress `
    --region $Region `
    --group-id $GroupId `
    --ip-permissions "IpProtocol=$Protocol,FromPort=$FromPort,ToPort=$ToPort,IpRanges=[{CidrIp=$Cidr}]" 2>&1
  if ($LASTEXITCODE -ne 0) {
    $joined = ($result | Out-String)
    if ($joined -notmatch "InvalidPermission\\.Duplicate") {
      $rule = "{0}:{1}-{2}" -f $Protocol, $FromPort, $ToPort
      throw "Failed to add ingress rule $rule $Cidr. Details: $joined"
    }
  }
}

Write-Host "Validating AWS CLI session..." -ForegroundColor Cyan
Invoke-AwsJson -AwsArgs @("sts", "get-caller-identity", "--output", "json") | Out-Null

if (-not $AmiId) {
  Write-Host "Resolving Ubuntu AMI from SSM..." -ForegroundColor Cyan
  try {
    $AmiId = Invoke-AwsText -AwsArgs @(
      "ssm", "get-parameter",
      "--region", $Region,
      "--name", "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id",
      "--query", "Parameter.Value",
      "--output", "text"
    )
  } catch {
    $AmiId = Invoke-AwsText -AwsArgs @(
      "ssm", "get-parameter",
      "--region", $Region,
      "--name", "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp3/ami-id",
      "--query", "Parameter.Value",
      "--output", "text"
    )
  }
}

if (-not $VpcId) {
  $VpcId = Invoke-AwsText -AwsArgs @(
    "ec2", "describe-vpcs",
    "--region", $Region,
    "--filters", "Name=isDefault,Values=true",
    "--query", "Vpcs[0].VpcId",
    "--output", "text"
  )
}
if (-not $VpcId -or $VpcId -eq "None") {
  throw "Could not determine VPC. Pass -VpcId explicitly."
}

if (-not $SubnetId) {
  $SubnetId = Invoke-AwsText -AwsArgs @(
    "ec2", "describe-subnets",
    "--region", $Region,
    "--filters", "Name=vpc-id,Values=$VpcId",
    "--query", "Subnets[?MapPublicIpOnLaunch==`true`]|[0].SubnetId",
    "--output", "text"
  )
  if (-not $SubnetId -or $SubnetId -eq "None") {
    $SubnetId = Invoke-AwsText -AwsArgs @(
      "ec2", "describe-subnets",
      "--region", $Region,
      "--filters", "Name=vpc-id,Values=$VpcId",
      "--query", "Subnets[0].SubnetId",
      "--output", "text"
    )
  }
}
if (-not $SubnetId -or $SubnetId -eq "None") {
  throw "Could not determine subnet. Pass -SubnetId explicitly."
}

if (-not $SecurityGroupId) {
  $sgName = "$NamePrefix-backend-sg"
  Write-Host "Creating or reusing security group '$sgName'..." -ForegroundColor Cyan
  try {
    $created = Invoke-AwsJson -AwsArgs @(
      "ec2", "create-security-group",
      "--region", $Region,
      "--group-name", $sgName,
      "--description", "PQmsg backend access",
      "--vpc-id", $VpcId,
      "--output", "json"
    )
    $SecurityGroupId = $created.GroupId
  } catch {
    $SecurityGroupId = Invoke-AwsText -AwsArgs @(
      "ec2", "describe-security-groups",
      "--region", $Region,
      "--filters", "Name=group-name,Values=$sgName", "Name=vpc-id,Values=$VpcId",
      "--query", "SecurityGroups[0].GroupId",
      "--output", "text"
    )
    if (-not $SecurityGroupId -or $SecurityGroupId -eq "None") {
      throw
    }
  }
}

if (-not $SshIngressCidr) {
  try {
    $publicIp = (Invoke-RestMethod -Uri "https://checkip.amazonaws.com").Trim()
    $SshIngressCidr = "$publicIp/32"
  } catch {
    Write-Warning "Could not auto-detect client IP for SSH. Pass -SshIngressCidr if you need SSH access."
  }
}

Write-Host "Configuring ingress rules..." -ForegroundColor Cyan
Add-IngressRule -Region $Region -GroupId $SecurityGroupId -Protocol tcp -FromPort 80 -ToPort 80 -Cidr "0.0.0.0/0"
Add-IngressRule -Region $Region -GroupId $SecurityGroupId -Protocol tcp -FromPort 443 -ToPort 443 -Cidr "0.0.0.0/0"
if ($SshIngressCidr) {
  Add-IngressRule -Region $Region -GroupId $SecurityGroupId -Protocol tcp -FromPort 22 -ToPort 22 -Cidr $SshIngressCidr
}

$userData = @'
#!/bin/bash
set -euxo pipefail
apt-get update -y
apt-get install -y ca-certificates curl gnupg lsb-release unzip jq
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo $VERSION_CODENAME) stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable docker
systemctl start docker
usermod -aG docker ubuntu
mkdir -p /opt/pqmsg
touch /opt/pqmsg/BOOTSTRAPPED_BY_user_data
chown -R ubuntu:ubuntu /opt/pqmsg
'@

$userDataFile = Join-Path $env:TEMP ("pqmsg-user-data-{0}.sh" -f ([Guid]::NewGuid().ToString("N")))
try {
  Set-Content -Path $userDataFile -Value $userData -Encoding utf8

  Write-Host "Launching EC2 instance..." -ForegroundColor Cyan
  $launch = Invoke-AwsJson -AwsArgs @(
    "ec2", "run-instances",
    "--region", $Region,
    "--image-id", $AmiId,
    "--instance-type", $InstanceType,
    "--key-name", $KeyName,
    "--security-group-ids", $SecurityGroupId,
    "--subnet-id", $SubnetId,
    "--associate-public-ip-address",
    "--user-data", "file://$userDataFile",
    "--tag-specifications", "ResourceType=instance,Tags=[{Key=Name,Value=$NamePrefix-backend}]", "ResourceType=volume,Tags=[{Key=Name,Value=$NamePrefix-backend}]",
    "--output", "json"
  )

  $instanceId = $launch.Instances[0].InstanceId
  if (-not $instanceId) {
    throw "Instance launch did not return an instance ID."
  }

  Write-Host "Waiting for instance to enter running state: $instanceId" -ForegroundColor Cyan
  & aws ec2 wait instance-running --region $Region --instance-ids $instanceId
  if ($LASTEXITCODE -ne 0) {
    throw "Timed out waiting for EC2 instance to reach running state."
  }

  $describe = Invoke-AwsJson -AwsArgs @(
    "ec2", "describe-instances",
    "--region", $Region,
    "--instance-ids", $instanceId,
    "--output", "json"
  )

  $instance = $describe.Reservations[0].Instances[0]
  $summary = [PSCustomObject]@{
    Region = $Region
    InstanceId = $instanceId
    InstanceType = $InstanceType
    AmiId = $AmiId
    VpcId = $VpcId
    SubnetId = $SubnetId
    SecurityGroupId = $SecurityGroupId
    PublicIpAddress = $instance.PublicIpAddress
    PublicDnsName = $instance.PublicDnsName
    KeyName = $KeyName
    SshIngressCidr = $SshIngressCidr
  }

  Write-Host "EC2 backend instance ready." -ForegroundColor Green
  $summary | ConvertTo-Json

  Write-Host "Next step:" -ForegroundColor Yellow
  Write-Host "  Run scripts/dev/aws/deploy_ec2_backend_stack.ps1 with this host and your SSH key file."
} finally {
  Remove-Item -Path $userDataFile -ErrorAction SilentlyContinue
}
