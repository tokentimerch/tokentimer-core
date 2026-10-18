<# Fixed test-only variant of the shared exact owned-tree observer. This phase
requires the new native binding with durable installing/bind, not a claim that
TLS verification has not run. Never selected by a release qualification lane. #>
param([Parameter(Mandatory)][string]$OwnedDirectory,[Parameter(Mandatory)][string]$ConfigDirectory,[Parameter(Mandatory)][string]$RepositoryRoot,[Parameter(Mandatory)][string]$NodeExecutable)
$ErrorActionPreference='Stop'
& (Join-Path $PSScriptRoot 'accepted-install-phase-fault.ps1') -OwnedDirectory $OwnedDirectory -ConfigDirectory $ConfigDirectory -RepositoryRoot $RepositoryRoot -NodeExecutable $NodeExecutable -Phase 'bound-before-complete'
