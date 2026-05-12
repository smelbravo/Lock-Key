<?php
/**
 * Lock & Key — Gerador de Ícones PNG para a Extensão Firefox
 * Aceder via: http://localhost/Lock%26Key/setup/generate_icons.php
 * Requer extensão GD do PHP (incluída no XAMPP por padrão)
 */

$outputDir = dirname(__DIR__) . '/extension/assets/';
if (!is_dir($outputDir)) {
    mkdir($outputDir, 0755, true);
}

$sizes = [16, 32, 48, 128];
$results = [];

foreach ($sizes as $size) {
    $img = imagecreatetruecolor($size, $size);
    imageantialias($img, true);

    // Cores
    $bg        = imagecolorallocate($img, 13,  17,  23);   // #0d1117 fundo escuro
    $accent    = imagecolorallocate($img, 31, 111, 235);   // #1f6feb azul
    $accentLight = imagecolorallocate($img, 88, 166, 255); // #58a6ff azul claro
    $white     = imagecolorallocate($img, 230, 237, 243);  // #e6edf3

    // Fundo arredondado (simular com círculo + rectângulo)
    $radius = (int)($size * 0.22);
    imagefilledrectangle($img, $radius, 0, $size - $radius, $size, $accent);
    imagefilledrectangle($img, 0, $radius, $size, $size - $radius, $accent);
    imagefilledellipse($img, $radius,          $radius,          $radius * 2, $radius * 2, $accent);
    imagefilledellipse($img, $size - $radius,  $radius,          $radius * 2, $radius * 2, $accent);
    imagefilledellipse($img, $radius,          $size - $radius,  $radius * 2, $radius * 2, $accent);
    imagefilledellipse($img, $size - $radius,  $size - $radius,  $radius * 2, $radius * 2, $accent);

    // Desenhar símbolo de cadeado
    $cx = (int)($size / 2);
    $cy = (int)($size / 2);

    // Corpo do cadeado (retângulo arredondado)
    $bw = (int)($size * 0.52); // largura
    $bh = (int)($size * 0.38); // altura
    $bx = $cx - (int)($bw / 2);
    $by = $cy - (int)($bh * 0.1);
    $br = max(2, (int)($size * 0.07));

    imagefilledrectangle($img, $bx + $br, $by,        $bx + $bw - $br, $by + $bh, $white);
    imagefilledrectangle($img, $bx,       $by + $br,  $bx + $bw,       $by + $bh, $white);
    imagefilledellipse($img, $bx + $br,       $by + $br, $br * 2, $br * 2, $white);
    imagefilledellipse($img, $bx + $bw - $br, $by + $br, $br * 2, $br * 2, $white);

    // Arco do cadeado (shackle)
    $sw  = (int)($size * 0.32); // largura do arco
    $sh  = (int)($size * 0.26); // altura do arco
    $sx  = $cx - (int)($sw / 2);
    $sy  = $by - $sh;
    $sth = max(2, (int)($size * 0.09)); // espessura da linha

    // Arco exterior
    imagefilledellipse($img, $cx, $by - (int)($sh * 0.5), $sw, $sh * 2, $white);
    // Arco interior (vazio — cor de fundo)
    $innerW = $sw - $sth * 2;
    $innerH = $sh * 2 - $sth * 2;
    if ($innerW > 2 && $innerH > 2) {
        imagefilledellipse($img, $cx, $by - (int)($sh * 0.5), $innerW, $innerH, $accent);
    }
    // Apagar a parte de baixo do arco (dentro do corpo)
    imagefilledrectangle($img, $sx, $by, $sx + $sw, $by + (int)($sth * 1.5), $white);

    // Buraco da chave (círculo + retângulo)
    $kh = max(2, (int)($size * 0.07));
    imagefilledellipse($img, $cx, $cy + (int)($bh * 0.15), $kh * 2, $kh * 2, $accent);
    imagefilledrectangle($img, $cx - (int)($kh * 0.5), $cy + (int)($bh * 0.15), $cx + (int)($kh * 0.5), $cy + (int)($bh * 0.5), $accent);

    // Guardar
    $filepath = $outputDir . "icon-{$size}.png";
    imagepng($img, $filepath, 9);
    imagedestroy($img);

    $results[] = ['size' => $size, 'path' => $filepath, 'exists' => file_exists($filepath)];
}

header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html lang="pt">
<head>
    <meta charset="UTF-8">
    <title>Lock & Key — Gerar Ícones</title>
    <style>
        body { font-family: system-ui; background:#0d1117; color:#e6edf3; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; }
        .card { background:#161b22; border:1px solid #30363d; border-radius:12px; padding:2rem; max-width:480px; width:100%; }
        h1 { color:#58a6ff; margin-bottom:1.5rem; }
        .item { display:flex; align-items:center; gap:1rem; padding:0.6rem 0; border-bottom:1px solid #30363d; }
        .item:last-child { border:none; }
        .ok  { color:#3fb950; font-size:1.2rem; }
        .err { color:#f85149; font-size:1.2rem; }
        .icon-preview { border:1px solid #30363d; border-radius:4px; padding:4px; background:#1f6feb22; }
        .info { background:#0d1b2e; border:1px solid #1f6feb; border-radius:8px; padding:1rem; margin-top:1.5rem; font-size:0.88rem; color:#58a6ff; }
        .warn { background:#2d1f09; border:1px solid #f0a500; border-radius:8px; padding:1rem; margin-top:1rem; font-size:0.85rem; color:#f0a500; }
    </style>
</head>
<body>
<div class="card">
    <h1>🔐 Ícones gerados</h1>
    <?php foreach ($results as $r): ?>
    <div class="item">
        <span class="<?= $r['exists'] ? 'ok' : 'err' ?>"><?= $r['exists'] ? '✅' : '❌' ?></span>
        <span>icon-<?= $r['size'] ?>.png</span>
        <?php if ($r['exists']): ?>
            <img class="icon-preview" src="../extension/assets/icon-<?= $r['size'] ?>.png" width="<?= min($r['size'], 48) ?>" height="<?= min($r['size'], 48) ?>" alt="icon-<?= $r['size'] ?>">
        <?php endif; ?>
    </div>
    <?php endforeach; ?>

    <div class="info">
        ✅ Ícones guardados em <code>extension/assets/</code><br><br>
        Agora vai ao Firefox → <strong>about:debugging</strong> → clica em <strong>"Recarregar"</strong> na extensão Lock &amp; Key.
    </div>
    <div class="warn">
        ⚠️ Após recarregar a extensão, podes apagar este ficheiro <code>setup/generate_icons.php</code>.
    </div>
</div>
</body>
</html>
