$ErrorActionPreference = 'Stop'
Set-Location 'C:\projects\post-quantum-messaging-app'
$env:PQMSG_WEB_HOST = '127.0.0.1'
$env:PQMSG_WEB_PORT = '8081'
$env:PQMSG_BACKEND_HOST = '127.0.0.1'
$env:PQMSG_BACKEND_PORT = '3000'
node scripts/dev/serve_local_web_production.mjs
