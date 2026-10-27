<#
    carto.ps1 - Cartographie du réseau maison avec nmap

    Ce que fait le script :
      1. Détecte tout seul le réseau de la connexion active (adresse + masque).
      2. Lance nmap : découverte des appareils + 1000 ports TCP les plus courants.
      3. Compare avec la liste des appareils connus (appareils-connus.csv).
      4. Génère une page HTML dans le dossier "rapports" et l'ouvre :
           - en rouge  : appareil jamais vu (NOUVEL APPAREIL)
           - en orange : appareil connu, mais avec un port ouvert inattendu
           - en gris   : appareil connu absent du scan (éteint, en veille...)

    Utilisation (PowerShell en administrateur) :
      Premier lancement : .\carto.ps1 -Init   -> crée appareils-connus.csv
      Ensuite          : .\carto.ps1

    À n'utiliser QUE sur un réseau qui t'appartient ou avec une autorisation écrite.
#>
param([switch]$Init)

$ErrorActionPreference = 'Stop'
$dossier         = $PSScriptRoot
$fichierConnus   = Join-Path $dossier 'appareils-connus.csv'
$dossierRapports = Join-Path $dossier 'rapports'

# Ports qui méritent une attention particulière s'ils sont ouverts
$portsSensibles = @{
    21   = 'FTP : transfert de fichiers non chiffré'
    23   = 'Telnet : accès à distance non chiffré, à fermer'
    135  = 'RPC Windows'
    139  = 'NetBIOS : ancien partage Windows'
    445  = 'SMB : partage de fichiers Windows (cible fréquente des ransomwares)'
    3389 = 'Bureau à distance Windows (RDP)'
    5900 = 'VNC : prise de contrôle à distance'
}

function E($texte) { [System.Net.WebUtility]::HtmlEncode([string]$texte) }

# --- 1. Vérifications -------------------------------------------------------
$identite = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identite.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Lance ce script en administrateur (nécessaire pour lire les adresses MAC)." -ForegroundColor Red
    exit 1
}

$nmap = (Get-Command nmap -ErrorAction SilentlyContinue).Source
if (-not $nmap) {
    $nmapDefaut = Join-Path ${env:ProgramFiles(x86)} 'Nmap\nmap.exe'
    if (Test-Path $nmapDefaut) { $nmap = $nmapDefaut }
    else {
        Write-Host "nmap est introuvable. Installe-le depuis https://nmap.org/download" -ForegroundColor Red
        exit 1
    }
}

# --- 2. Détection du réseau -------------------------------------------------
$config = Get-NetIPConfiguration |
    Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } |
    Select-Object -First 1
if (-not $config) {
    Write-Host "Aucune connexion réseau active trouvée." -ForegroundColor Red
    exit 1
}

$ipPc       = $config.IPv4Address[0].IPAddress
$prefixe    = [int]$config.IPv4Address[0].PrefixLength
$passerelle = $config.IPv4DefaultGateway[0].NextHop
$macPc      = ($config.NetAdapter.MacAddress -replace '-', ':').ToUpper()

if ($prefixe -lt 22) {
    Write-Host "Réseau trop grand (/$prefixe) pour un scan domestique, arrêt." -ForegroundColor Red
    exit 1
}

# Calcul de l'adresse du réseau : IP du PC ET masque
$octetsIp = ([System.Net.IPAddress]::Parse($ipPc)).GetAddressBytes()
[Array]::Reverse($octetsIp)
$ipNum     = [BitConverter]::ToUInt32($octetsIp, 0)
$masqueNum = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $prefixe))
$reseauNum = [uint32]($ipNum -band $masqueNum)
$octetsRes = [BitConverter]::GetBytes($reseauNum)
[Array]::Reverse($octetsRes)
$reseau    = "$(([System.Net.IPAddress]$octetsRes).ToString())/$prefixe"

# --- 3. Scan nmap ------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $dossierRapports | Out-Null
$horodatage = Get-Date -Format 'yyyy-MM-dd_HHmm'
$fichierXml = Join-Path $dossierRapports "scan-$horodatage.xml"

Write-Host ""
Write-Host "Réseau détecté : $reseau  (ton PC : $ipPc, box : $passerelle)" -ForegroundColor Cyan
Write-Host "Scan en cours, compte 1 à 3 minutes..." -ForegroundColor Cyan
& $nmap -T4 -oX $fichierXml $reseau | Out-Null

[xml]$scan = Get-Content -Path $fichierXml -Raw -Encoding UTF8

$appareils = @(foreach ($h in $scan.nmaprun.host) {
    if ($h.status.state -ne 'up') { continue }

    $ip      = ($h.address | Where-Object { $_.addrtype -eq 'ipv4' }).addr
    $macNode = $h.address | Where-Object { $_.addrtype -eq 'mac' }
    $mac = ''
    $fabricant = ''
    if ($macNode) {
        $mac = ([string]$macNode.addr).ToUpper()
        $fabricant = [string]$macNode.vendor
    } elseif ($ip -eq $ipPc) {
        $mac = $macPc
        $fabricant = '(ce PC)'
    }

    $nomHote = ''
    if ($h.hostnames -and $h.hostnames.hostname) {
        $nomHote = [string](@($h.hostnames.hostname)[0].name)
    }

    $ports = @()
    if ($h.ports -and $h.ports.port) {
        $ports = @($h.ports.port |
            Where-Object { $_.state.state -eq 'open' } |
            ForEach-Object { [pscustomobject]@{ Num = [int]$_.portid; Service = [string]$_.service.name } } |
            Sort-Object Num)
    }

    [pscustomobject]@{ IP = $ip; MAC = $mac; Fabricant = $fabricant; NomHote = $nomHote; Ports = $ports }
})

if ($appareils.Count -eq 0) {
    Write-Host "Aucun appareil trouvé. Vérifie ta connexion." -ForegroundColor Red
    exit 1
}

# --- 4. Création de la liste des appareils connus (premier lancement) --------
if ($Init -or -not (Test-Path $fichierConnus)) {
    if (Test-Path $fichierConnus) {
        Copy-Item $fichierConnus "$fichierConnus.ancien" -Force
        Write-Host "Ancienne liste sauvegardée dans appareils-connus.csv.ancien" -ForegroundColor Yellow
    }
    $appareils | ForEach-Object {
        $nom = if ($_.NomHote) { $_.NomHote } else { $_.IP }
        [pscustomobject]@{
            Nom           = $nom
            MAC           = $_.MAC
            NomHote       = $_.NomHote
            PortsAttendus = (@($_.Ports | ForEach-Object { $_.Num }) -join ' ')
        }
    } | Export-Csv -Path $fichierConnus -Delimiter ';' -NoTypeInformation -Encoding UTF8
    Write-Host ""
    Write-Host "Liste des appareils connus créée : $fichierConnus" -ForegroundColor Green
    Write-Host "Ouvre-la avec le Bloc-notes et remplace la colonne Nom par des noms clairs (TV salon, Clim chambre...)." -ForegroundColor Green
}

$connus = @(Import-Csv -Path $fichierConnus -Delimiter ';' -Encoding UTF8)

# --- 5. Comparaison ------------------------------------------------------------
$resultats = @(foreach ($a in $appareils) {
    $c = $null
    if ($a.MAC) { $c = $connus | Where-Object { $_.MAC -and $_.MAC.ToUpper() -eq $a.MAC } | Select-Object -First 1 }
    if (-not $c -and $a.NomHote) { $c = $connus | Where-Object { $_.NomHote -and $_.NomHote -eq $a.NomHote } | Select-Object -First 1 }

    $attendus = @()
    if ($c -and $c.PortsAttendus) {
        $attendus = @($c.PortsAttendus -split '\s+' | Where-Object { $_ } | ForEach-Object { [int]$_ })
    }
    $inattendus = @($a.Ports | Where-Object { $attendus -notcontains $_.Num } | ForEach-Object { $_.Num })

    if (-not $c)                   { $statut = 'nouveau'; $nom = 'Appareil inconnu' }
    elseif ($inattendus.Count -gt 0) { $statut = 'ports';   $nom = $c.Nom }
    else                           { $statut = 'ok';      $nom = $c.Nom }

    [pscustomobject]@{
        Nom = $nom; IP = $a.IP; MAC = $a.MAC; Fabricant = $a.Fabricant; NomHote = $a.NomHote
        Ports = $a.Ports; Inattendus = $inattendus; Statut = $statut
    }
})

$absents = @($connus | Where-Object {
    $mac = $_.MAC; $nh = $_.NomHote
    -not ($appareils | Where-Object { ($mac -and $_.MAC -eq $mac.ToUpper()) -or ($nh -and $_.NomHote -eq $nh) })
})

$nbNouveaux = @($resultats | Where-Object { $_.Statut -eq 'nouveau' }).Count
$nbPorts    = @($resultats | Where-Object { $_.Statut -eq 'ports' }).Count

# --- 6. Page HTML --------------------------------------------------------------
$lignesHtml = foreach ($r in ($resultats | Sort-Object { [version]$_.IP })) {
    switch ($r.Statut) {
        'nouveau' { $classe = 'alerte';    $badge = 'NOUVEL APPAREIL' }
        'ports'   { $classe = 'attention'; $badge = 'PORT INATTENDU' }
        default   { $classe = 'ok';        $badge = 'Connu' }
    }

    $fab = $r.Fabricant
    if (-not $fab -and $r.MAC.Length -ge 2 -and '2', '6', 'A', 'E' -contains $r.MAC.Substring(1, 1)) {
        $fab = 'MAC aléatoire (téléphone ?)'
    } elseif (-not $fab) { $fab = 'Inconnu' }

    if ($r.Ports.Count -gt 0) {
        $portsHtml = ($r.Ports | ForEach-Object {
            $classes = @('port')
            if ($r.Inattendus -contains $_.Num) { $classes += 'inattendu' }
            $titre = ''
            if ($portsSensibles.ContainsKey($_.Num)) { $classes += 'sensible'; $titre = $portsSensibles[$_.Num] }
            "<span class='$($classes -join ' ')' title='$(E $titre)'>$($_.Num)<small>$(E $_.Service)</small></span>"
        }) -join ' '
    } else {
        $portsHtml = "<span class='vide'>aucun</span>"
    }

    $role = ''
    if ($r.IP -eq $passerelle) { $role = ' <em>(box)</em>' }
    elseif ($r.IP -eq $ipPc)   { $role = ' <em>(ce PC)</em>' }

    @"
<tr class='$classe'>
  <td><span class='badge'>$badge</span></td>
  <td><strong>$(E $r.Nom)</strong>$role<br><small>$(E $r.NomHote)</small></td>
  <td><code>$(E $r.IP)</code></td>
  <td><code>$(E $r.MAC)</code><br><small>$(E $fab)</small></td>
  <td>$portsHtml</td>
</tr>
"@
}

$absentsHtml = ''
if ($absents.Count -gt 0) {
    $items = ($absents | ForEach-Object { "<li><strong>$(E $_.Nom)</strong> <small>$(E $_.MAC)</small></li>" }) -join ''
    $absentsHtml = "<h2>Appareils connus absents de ce scan</h2><p class='note'>Éteints, en veille ou déconnectés : un scan est une photo à un instant donné.</p><ul class='absents'>$items</ul>"
}

$dateLisible = Get-Date -Format 'dddd d MMMM yyyy à HH:mm'
$verdict = if ($nbNouveaux -gt 0) { "<div class='verdict rouge'>$nbNouveaux appareil(s) inconnu(s) sur le réseau : à identifier.</div>" }
           elseif ($nbPorts -gt 0) { "<div class='verdict orange'>Aucun intrus, mais $nbPorts appareil(s) avec un port inattendu.</div>" }
           else { "<div class='verdict vert'>Tout est normal : aucun appareil inconnu, aucun port inattendu.</div>" }

$html = @"
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Carte du réseau - $horodatage</title>
<style>
  body { font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; padding: 24px; background: #f4f6f8; color: #1c2430; }
  h1 { margin: 0 0 4px; font-size: 26px; }
  h2 { font-size: 18px; margin-top: 32px; }
  .sous-titre { color: #5b6675; margin-bottom: 20px; }
  .chiffres { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px; }
  .chiffre { background: #fff; border-radius: 10px; padding: 12px 18px; box-shadow: 0 1px 3px rgba(0,0,0,.08); min-width: 120px; }
  .chiffre b { display: block; font-size: 26px; }
  .verdict { padding: 12px 16px; border-radius: 10px; font-weight: 600; margin-bottom: 20px; }
  .verdict.vert { background: #e3f6e8; color: #1d6b34; }
  .verdict.orange { background: #fff1dc; color: #8a5300; }
  .verdict.rouge { background: #fde4e4; color: #a01d1d; }
  table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 10px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #e8ecf0; vertical-align: top; font-size: 14px; }
  th { background: #1c2430; color: #fff; font-weight: 600; }
  small { color: #6b7684; }
  code { font-size: 13px; }
  .badge { font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 20px; white-space: nowrap; }
  tr.ok .badge { background: #e3f6e8; color: #1d6b34; }
  tr.attention { background: #fffaf2; }
  tr.attention .badge { background: #ffd89e; color: #6b4000; }
  tr.alerte { background: #fff5f5; }
  tr.alerte .badge { background: #e53935; color: #fff; }
  .port { display: inline-block; background: #eef1f4; border-radius: 6px; padding: 2px 7px; margin: 2px 2px 2px 0; font-family: Consolas, monospace; font-size: 13px; }
  .port small { margin-left: 5px; font-family: 'Segoe UI', sans-serif; }
  .port.sensible { border: 1px solid #e0a100; }
  .port.inattendu { background: #e53935; color: #fff; }
  .port.inattendu small { color: #ffe0e0; }
  .vide { color: #9aa4b0; font-style: italic; }
  .absents li { margin: 4px 0; }
  .note, .legende { color: #5b6675; font-size: 13px; }
  .legende { margin-top: 28px; line-height: 1.7; }
  @media (max-width: 700px) { body { padding: 12px; } th:nth-child(4), td:nth-child(4) { display: none; } }
</style>
</head>
<body>
  <h1>Carte du réseau maison</h1>
  <div class="sous-titre">Scan du $dateLisible &middot; réseau <code>$reseau</code> &middot; box <code>$passerelle</code></div>
  <div class="chiffres">
    <div class="chiffre"><b>$($resultats.Count)</b>appareils actifs</div>
    <div class="chiffre"><b>$nbNouveaux</b>inconnus</div>
    <div class="chiffre"><b>$nbPorts</b>ports inattendus</div>
    <div class="chiffre"><b>$($absents.Count)</b>connus absents</div>
  </div>
  $verdict
  <table>
    <tr><th>Statut</th><th>Appareil</th><th>Adresse IP</th><th>MAC / fabricant</th><th>Ports ouverts</th></tr>
    $($lignesHtml -join "`n")
  </table>
  $absentsHtml
  <div class="legende">
    <b>Légende.</b> Port <span class="port inattendu">rouge</span> : ouvert alors qu'il n'est pas dans la liste des ports attendus.
    Port <span class="port sensible">encadré</span> : port sensible, survole-le pour l'explication.
    Le service affiché à côté du port est deviné par nmap d'après son numéro.<br>
    Ton propre PC se scanne sans passer par son pare-feu : ses ports ouverts ne sont pas forcément visibles depuis les autres appareils.<br>
    Fichier brut du scan : <code>scan-$horodatage.xml</code>
  </div>
</body>
</html>
"@

$fichierHtml = Join-Path $dossierRapports "carte-$horodatage.html"
Set-Content -Path $fichierHtml -Value $html -Encoding UTF8

# --- 7. Résumé dans la console -------------------------------------------------
Write-Host ""
Write-Host "$($resultats.Count) appareils actifs, $nbNouveaux inconnu(s), $nbPorts avec port inattendu, $($absents.Count) absent(s)." -ForegroundColor Cyan
foreach ($r in ($resultats | Where-Object { $_.Statut -ne 'ok' })) {
    if ($r.Statut -eq 'nouveau') { Write-Host "  NOUVEL APPAREIL : $($r.IP)  $($r.MAC)  $($r.Fabricant)" -ForegroundColor Red }
    else { Write-Host "  PORT INATTENDU  : $($r.Nom) ($($r.IP)) -> $($r.Inattendus -join ', ')" -ForegroundColor Yellow }
}
Write-Host "Rapport : $fichierHtml" -ForegroundColor Green
Start-Process $fichierHtml
