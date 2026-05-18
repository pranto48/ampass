# AMPass — Generate App Icons
# Creates valid .ico and .png icon files for the Tauri desktop app.
# Uses .NET System.Drawing to create a simple AMPass shield icon.

Add-Type -AssemblyName System.Drawing

$iconDir = Join-Path $PSScriptRoot "..\clients\desktop-tauri\src-tauri\icons"

function New-AMPassIcon([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap($size, $size)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::Transparent)

    # Background rounded rect (indigo gradient approximation)
    $bgBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 79, 70, 229))
    $radius = [int]($size * 0.2)
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddArc(0, 0, $radius, $radius, 180, 90)
    $path.AddArc($size - $radius, 0, $radius, $radius, 270, 90)
    $path.AddArc($size - $radius, $size - $radius, $radius, $radius, 0, 90)
    $path.AddArc(0, $size - $radius, $radius, $radius, 90, 90)
    $path.CloseFigure()
    $g.FillPath($bgBrush, $path)

    # Shield shape (white)
    $shieldBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(230, 255, 255, 255))
    $cx = $size / 2
    $cy = $size / 2
    $sw = $size * 0.4  # shield width
    $sh = $size * 0.5  # shield height
    $top = $cy - $sh * 0.45

    $shieldPath = New-Object System.Drawing.Drawing2D.GraphicsPath
    $shieldPath.AddLine([float]($cx), [float]$top, [float]($cx + $sw/2), [float]($top + $sh * 0.25))
    $shieldPath.AddLine([float]($cx + $sw/2), [float]($top + $sh * 0.25), [float]($cx + $sw/2), [float]($top + $sh * 0.55))
    $shieldPath.AddBezier(
        [float]($cx + $sw/2), [float]($top + $sh * 0.55),
        [float]($cx + $sw/3), [float]($top + $sh * 0.85),
        [float]($cx + $sw/6), [float]($top + $sh * 0.95),
        [float]$cx, [float]($top + $sh)
    )
    $shieldPath.AddBezier(
        [float]$cx, [float]($top + $sh),
        [float]($cx - $sw/6), [float]($top + $sh * 0.95),
        [float]($cx - $sw/3), [float]($top + $sh * 0.85),
        [float]($cx - $sw/2), [float]($top + $sh * 0.55)
    )
    $shieldPath.AddLine([float]($cx - $sw/2), [float]($top + $sh * 0.55), [float]($cx - $sw/2), [float]($top + $sh * 0.25))
    $shieldPath.CloseFigure()
    $g.FillPath($shieldBrush, $shieldPath)

    $g.Dispose()
    return $bmp
}

function Save-Ico([System.Drawing.Bitmap[]]$bitmaps, [string]$path) {
    # ICO file format: header + directory entries + image data
    $ms = New-Object System.IO.MemoryStream

    $writer = New-Object System.IO.BinaryWriter($ms)

    # ICO Header
    $writer.Write([uint16]0)       # Reserved
    $writer.Write([uint16]1)       # Type: 1 = ICO
    $writer.Write([uint16]$bitmaps.Count) # Number of images

    # Calculate offsets
    $headerSize = 6 + ($bitmaps.Count * 16)
    $imageDataList = @()

    foreach ($bmp in $bitmaps) {
        $pngStream = New-Object System.IO.MemoryStream
        $bmp.Save($pngStream, [System.Drawing.Imaging.ImageFormat]::Png)
        $imageDataList += ,$pngStream.ToArray()
        $pngStream.Dispose()
    }

    # Directory entries
    $offset = $headerSize
    for ($i = 0; $i -lt $bitmaps.Count; $i++) {
        $bmp = $bitmaps[$i]
        $data = $imageDataList[$i]
        $w = if ($bmp.Width -ge 256) { 0 } else { [byte]$bmp.Width }
        $h = if ($bmp.Height -ge 256) { 0 } else { [byte]$bmp.Height }

        $writer.Write([byte]$w)          # Width
        $writer.Write([byte]$h)          # Height
        $writer.Write([byte]0)           # Color palette
        $writer.Write([byte]0)           # Reserved
        $writer.Write([uint16]1)         # Color planes
        $writer.Write([uint16]32)        # Bits per pixel
        $writer.Write([uint32]$data.Length) # Image data size
        $writer.Write([uint32]$offset)   # Offset to image data
        $offset += $data.Length
    }

    # Image data
    foreach ($data in $imageDataList) {
        $writer.Write($data)
    }

    $writer.Flush()
    [System.IO.File]::WriteAllBytes($path, $ms.ToArray())
    $ms.Dispose()
}

Write-Host "Generating AMPass icons..."

# Generate PNGs
$sizes = @(16, 32, 48, 64, 128, 256)
$bitmaps = @()

foreach ($size in $sizes) {
    $bmp = New-AMPassIcon $size
    $bitmaps += $bmp

    # Save individual PNGs for sizes Tauri needs
    if ($size -eq 32) {
        $bmp.Save((Join-Path $iconDir "32x32.png"), [System.Drawing.Imaging.ImageFormat]::Png)
        Write-Host "  Created 32x32.png"
    }
    if ($size -eq 128) {
        $bmp.Save((Join-Path $iconDir "128x128.png"), [System.Drawing.Imaging.ImageFormat]::Png)
        Write-Host "  Created 128x128.png"
    }
}

# Save icon.png (256x256)
$bitmaps[-1].Save((Join-Path $iconDir "icon.png"), [System.Drawing.Imaging.ImageFormat]::Png)
Write-Host "  Created icon.png (256x256)"

# Save ICO with all sizes
Save-Ico $bitmaps (Join-Path $iconDir "icon.ico")
Write-Host "  Created icon.ico (16,32,48,64,128,256)"

# Cleanup
foreach ($bmp in $bitmaps) { $bmp.Dispose() }

Write-Host ""
Write-Host "Done! Icons saved to: $iconDir" -ForegroundColor Green
