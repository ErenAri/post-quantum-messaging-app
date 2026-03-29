$ErrorActionPreference = 'Stop'

Set-Location 'C:\projects\post-quantum-messaging-app'

$env:PQMSG_DATABASE_URL = 'sqlite://./pqmsg-server.db?mode=rwc'
$env:PQMSG_BIND = '127.0.0.1:3000'
$env:PQMSG_SECURITY_PROFILE = 'research'
$env:PQMSG_WEB_CLIENT_POLICY = 'interop_candidate'
$env:PQMSG_CORS_ALLOWED_ORIGINS = 'http://localhost:4173,http://127.0.0.1:4173,http://localhost:5173,http://127.0.0.1:5173'

cargo run -p pqmsg-server --bin pqmsg-server
