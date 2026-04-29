param(
    [switch]$Build,
    [switch]$Up,
    [switch]$Down
)

if ($Build) {
    docker build -t scanlitee .
} elseif ($Up) {
    docker compose up --build
} elseif ($Down) {
    docker compose down
} else {
    Write-Host "Usage: .\deploy.ps1 -Build | -Up | -Down"
    Write-Host "  -Build   Build the Docker image"
    Write-Host "  -Up      Start the full Docker Compose stack"
    Write-Host "  -Down    Stop the Docker Compose stack"
}
