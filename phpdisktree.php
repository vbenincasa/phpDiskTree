<?php
/**
 * phpDiskTree (single-file)
 * - Full disk usage scan with persistent cache (SLIM)
 * - Navigation by cached tree
 * - Top largest files + top largest folders
 * - Selection list stored in browser (localStorage), isolated per installation (root hash)
 * - Multi-language (PT/EN) auto by browser + language selector
 *
 * Author: Victor Benincasa (https://github.com/vbenincasa/phpDiskTree)
 */

declare(strict_types=1);
session_start();


// -------------------------- Autenticação --------------------------
// Deixe em branco ('') para desabilitar autenticação
$AUTH_PASSWORD = ''; // ← DEFINA SUA SENHA AQUI

// Opcional: Timeout de sessão em segundos (padrão: 30 minutos)
$AUTH_SESSION_TIMEOUT = 1800;


// -------------------------- Config --------------------------
$ROOT_DIR = realpath(__DIR__) ?: __DIR__;
$APP_NAME = 'phpDiskTree';
$APP_VERSION = '1.0-beta';

$CACHE_PREFIX = 'phpdisktree_cache';
$ROOT_HASH = sha1($ROOT_DIR);
$CACHE_FILE = $ROOT_DIR . DIRECTORY_SEPARATOR . ($CACHE_PREFIX . '_' . $ROOT_HASH . '.json');

$LOCK_FILE  = $ROOT_DIR . DIRECTORY_SEPARATOR . ($CACHE_PREFIX . '_' . $ROOT_HASH . '.lock');
$LOCK_STALE_SECONDS = 3 * 60 * 60; // 3h
$CACHE_STALE_SECONDS = 12 * 60 * 60; // 12h (UI warning)

$SCRIPT_BASENAME = basename(__FILE__);

// Top lists
$TOP_FILES_N = 300; // stored
$TOP_DIRS_N  = 250; // stored
$TOP_SHOW_N  = 80;  // shown in UI

// Memory safety (best-effort)
$MEM_CHECK_EVERY = 60000;
$MEM_ABORT_AT = 0.88;

// Pagination defaults
$DEFAULT_PAGE_SIZE = 150;


// ==================== SISTEMA DE AUTENTICAÇÃO ====================
if ($AUTH_PASSWORD !== '') {
    // Processar logout
    if (isset($_GET['logout'])) {
        session_destroy();
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }
    
    // Verificar timeout de sessão
    if (isset($_SESSION['phpdisktree_login_time'])) {
        if (time() - $_SESSION['phpdisktree_login_time'] > $AUTH_SESSION_TIMEOUT) {
            session_destroy();
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
        }
        $_SESSION['phpdisktree_login_time'] = time(); // Renovar
    }
    
    // Verificar se está autenticado
    if (!isset($_SESSION['phpdisktree_authenticated'])) {
        $login_error = '';
        
        // Processar tentativa de login
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
            if ($_POST['password'] === $AUTH_PASSWORD) {
                session_regenerate_id(true);
                $_SESSION['phpdisktree_authenticated'] = true;
                $_SESSION['phpdisktree_login_time'] = time();
                header('Location: ' . $_SERVER['PHP_SELF']);
                exit;
            } else {
                $login_error = 'Senha incorreta';
                sleep(1); // Prevenir brute force
            }
        }
        
        // Mostrar formulário de login
        ?>
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login - <?php echo htmlspecialchars($APP_NAME); ?></title>			
            <!-- Bootstrap -->
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.8/css/bootstrap.min.css" referrerpolicy="no-referrer">
            <!-- Bootstrap Icons -->
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/1.13.1/font/bootstrap-icons.min.css" referrerpolicy="no-referrer">
			
            <style>
                body {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .login-card {
                    max-width: 420px;
                    width: 100%;
                }
                .login-icon {
                    font-size: 3rem;
                    color: #667eea;
                }
				.brand-pill {
					display:inline-flex; align-items:center; gap:.6rem;
					padding:.35rem .75rem; border-radius: 999px;
					background: rgba(255,255,255,.72);
					border: 1px solid rgba(0,0,0,.08);
				}
				.brand-pill .logo {
					width: 34px; height: 34px; border-radius: 12px;
					display:flex; align-items:center; justify-content:center;
					background: rgba(13,110,253,.10);
					border: 1px solid rgba(0,0,0,.06);
				}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="row justify-content-center">
                    <div class="col-12 col-md-10 col-lg-8">
                        <div class="card login-card shadow-lg">
                            <div class="card-body p-5">
                                <div class="text-center mb-4">
									<div class="brand-pill mb-3">
									<div class="logo"><i class="bi bi-filetype-php fs-4 text-primary"></i></div>
									<div class="lh-sm">
									<div class="fw-semibold"><?php echo h($APP_NAME); ?></div>
									<div class="small muted" data-i18n="subtitle">Disk usage explorer</div>
									</div>
									</div>
                                </div>
                                
                                <?php if ($login_error): ?>
                                <div class="alert alert-danger d-flex align-items-center" role="alert">
                                    <i class="bi bi-exclamation-triangle-fill me-2"></i>
                                    <div><?php echo htmlspecialchars($login_error); ?></div>
                                </div>
                                <?php endif; ?>
                                
                                <form method="POST" action="">
                                    <div class="mb-4">
                                        <label for="password" class="form-label fw-semibold">Senha</label>
                                        <div class="input-group input-group-lg">
                                            <span class="input-group-text">
                                                <i class="bi bi-key-fill"></i>
                                            </span>
                                            <input 
                                                type="password" 
                                                class="form-control" 
                                                id="password" 
                                                name="password" 
                                                placeholder="Digite sua senha"
                                                required 
                                                autofocus
                                            >
                                        </div>
                                    </div>
                                    <div class="d-grid">
                                        <button type="submit" class="btn btn-primary btn-lg">
                                            <i class="bi bi-box-arrow-in-right me-2"></i>
                                            Entrar
                                        </button>
                                    </div>
                                </form>
                                
                                <div class="text-center mt-4">
                                    <small class="text-muted">
                                        <i class="bi bi-info-circle me-1"></i>
                                        Para desabilitar a autenticação, deixe $AUTH_PASSWORD vazio
                                    </small>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
}
// ==================== FIM DA AUTENTICAÇÃO ====================


// -------------------------- Helpers --------------------------
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

function starts_with(string $haystack, string $needle): bool {
    if ($needle === '') return true;
    return substr($haystack, 0, strlen($needle)) === $needle;
}

function normalize_rel(string $rel): string {
    $rel = str_replace('\\', '/', $rel);
    $rel = preg_replace('~/+~', '/', $rel);
    $rel = trim($rel, '/');
    if ($rel === '.' || $rel === './' || $rel === '/') return '';
    return $rel;
}

function abs_to_rel(string $root, string $abs): string {
    $rootN = str_replace('\\', '/', rtrim($root, '/\\')) . '/';
    $absN  = str_replace('\\', '/', $abs);
    if (starts_with($absN, $rootN)) {
        return normalize_rel(substr($absN, strlen($rootN)));
    }
    return '';
}

function safe_filemtime(string $path): int {
    $t = @filemtime($path);
    return is_int($t) ? $t : 0;
}

function get_memory_limit_bytes(): int {
    $v = ini_get('memory_limit');
    if (!is_string($v) || $v === '' || $v === '-1') return -1;
    $v = trim($v);
    $unit = strtolower(substr($v, -1));
    $num = (int)$v;
    if ($unit === 'g') return $num * 1024 * 1024 * 1024;
    if ($unit === 'm') return $num * 1024 * 1024;
    if ($unit === 'k') return $num * 1024;
    return (int)$v;
}

function json_response(array $payload, int $status = 200): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function read_cache(string $cacheFile): ?array {
    if (!is_file($cacheFile)) return null;
    $raw = @file_get_contents($cacheFile);
    if (!is_string($raw) || $raw === '') return null;
    $data = json_decode($raw, true);
    return is_array($data) ? $data : null;
}

function write_cache_atomic(string $cacheFile, array $data): void {
    $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;
    if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
    elseif (defined('JSON_INVALID_UTF8_IGNORE')) $flags |= JSON_INVALID_UTF8_IGNORE;

    $json = json_encode($data, $flags);
    if ($json === false) {
        throw new RuntimeException('Falha ao gerar JSON da varredura: ' . json_last_error_msg());
    }

    $tmp = $cacheFile . '.tmp';
    $ok = @file_put_contents($tmp, $json, LOCK_EX);
    if ($ok === false) {
        throw new RuntimeException('Falha ao gravar cache (sem permissão de escrita?).');
    }

    if (!@rename($tmp, $cacheFile)) {
        $copied = @copy($tmp, $cacheFile);
        @unlink($tmp);
        if (!$copied) {
            throw new RuntimeException('Falha ao substituir cache (rename/copy).');
        }
    }
    @chmod($cacheFile, 0644);
}

function get_csrf_token(): string {
    if (empty($_SESSION['phpdisktree_csrf']) || !is_string($_SESSION['phpdisktree_csrf'])) {
        $_SESSION['phpdisktree_csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['phpdisktree_csrf'];
}

function require_csrf(): void {
    $expected = $_SESSION['phpdisktree_csrf'] ?? '';
    $given = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!is_string($expected)) $expected = '';
    if (!is_string($given)) $given = '';
    if ($expected === '' || !hash_equals($expected, $given)) {
        json_response(['ok' => false, 'error' => 'CSRF inválido. Recarregue a página e tente novamente.'], 403);
    }
}

function lock_status(string $lockFile, int $staleSeconds): array {
    if (!is_file($lockFile)) return ['exists' => false, 'stale' => false, 'age_sec' => 0];
    $mtime = safe_filemtime($lockFile);
    $age = max(0, time() - $mtime);
    return ['exists' => true, 'stale' => ($age > $staleSeconds), 'age_sec' => $age];
}

function acquire_lock(string $lockFile, int $staleSeconds) {
    // remove stale lock
    if (is_file($lockFile)) {
        $st = lock_status($lockFile, $staleSeconds);
        if ($st['exists'] && $st['stale']) @unlink($lockFile);
    }

    $fh = @fopen($lockFile, 'c+');
    if ($fh === false) throw new RuntimeException('Não foi possível abrir lockfile (permissões?).');

    if (!@flock($fh, LOCK_EX | LOCK_NB)) {
        @fclose($fh);
        throw new RuntimeException('Uma varredura já está em andamento. Aguarde terminar.');
    }

    // write heartbeat
    @ftruncate($fh, 0);
    @fwrite($fh, (string)time());
    @fflush($fh);

    return $fh;
}

function release_lock($fh, string $lockFile): void {
    if (is_resource($fh)) {
        @flock($fh, LOCK_UN);
        @fclose($fh);
    }
    @unlink($lockFile);
}

function resolve_dir(string $rootDir, string $rel): array {
    $rootReal = realpath($rootDir) ?: $rootDir;
    $rel = normalize_rel($rel);
    if ($rel === '') return [$rootReal, ''];

    $candidate = realpath($rootReal . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $rel));
    if ($candidate === false || !is_dir($candidate)) return [$rootReal, ''];

    // Ensure candidate inside root
    $rootPrefix = rtrim($rootReal, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    $candPrefix = rtrim($candidate, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    if ($candidate !== $rootReal && substr($candPrefix, 0, strlen($rootPrefix)) !== $rootPrefix) {
        return [$rootReal, ''];
    }
    return [$candidate, $rel];
}

function build_breadcrumb(string $relPath): array {
    $parts = array_values(array_filter(explode('/', trim($relPath, '/')), fn($p)=>$p!==''));
    $crumbs = [];
    $acc = '';
    foreach ($parts as $p) {
        $acc = ($acc === '') ? $p : ($acc . '/' . $p);
        $crumbs[] = ['label' => $p, 'p' => $acc];
    }
    return $crumbs;
}

// -------------------------- Scanner (SLIM cache) --------------------------
function scan_full_tree_slim(
    string $rootDir,
    string $cachePrefix,
    string $scriptBasename,
    string $cacheFileBasename,
    string $lockFile,
    int $topFilesN,
    int $topDirsN,
    int $memCheckEvery,
    float $memAbortAt
): array {
    @set_time_limit(0);
    if (function_exists('ignore_user_abort')) @ignore_user_abort(true);

    $t0 = microtime(true);
    $rootReal = realpath($rootDir) ?: $rootDir;

    $scannedAt = time();
    $memLimit = get_memory_limit_bytes();

    $dirs = [];
    $dirs[''] = [
        'm' => safe_filemtime($rootReal),
        'd' => [],
        'f' => [],
        'ds' => 0,
        'dfc' => 0,
        't' => 0, 'fc' => 0, 'dc' => 0
    ];

    $pqFiles = new SplPriorityQueue();
    $pqFiles->setExtractFlags(SplPriorityQueue::EXTR_BOTH);

    $count = 0;

    $rdi = new RecursiveDirectoryIterator(
        $rootReal,
        FilesystemIterator::SKIP_DOTS
        | FilesystemIterator::CURRENT_AS_FILEINFO
        | FilesystemIterator::KEY_AS_PATHNAME
    );

    $it = new RecursiveIteratorIterator(
        $rdi,
        RecursiveIteratorIterator::SELF_FIRST,
        RecursiveIteratorIterator::CATCH_GET_CHILD
    );

    foreach ($it as $abs => $info) {
        $count++;

        if (($count % 20000) === 0) {
            @touch($lockFile);
        }
        if ($memLimit > 0 && ($count % max(1, $memCheckEvery)) === 0) {
            $usage = memory_get_usage(true);
            if ($usage > (int)($memLimit * $memAbortAt)) {
                throw new RuntimeException('Memória insuficiente durante a varredura. Aumente memory_limit no PHP.');
            }
        }

        try {
            if (!$info instanceof SplFileInfo) continue;
            if ($info->isLink()) continue;

            $rel = abs_to_rel($rootReal, $info->getPathname());
            $base = basename(str_replace('\\', '/', $rel));

            // ignore cache + lock + script
            if ($base !== '' && (
                starts_with($base, $cachePrefix) ||
                $base === $scriptBasename ||
                $base === $cacheFileBasename ||
                $base === basename($lockFile)
            )) {
                continue;
            }

            if ($info->isDir()) {
                $dirRel = normalize_rel($rel);
                if (!isset($dirs[$dirRel])) {
                    $dirs[$dirRel] = [
                        'm' => safe_filemtime($info->getPathname()),
                        'd' => [],
                        'f' => [],
                        'ds' => 0,
                        'dfc' => 0,
                        't' => 0, 'fc' => 0, 'dc' => 0
                    ];
                }

                if ($dirRel !== '') {
                    $parentRel = normalize_rel(dirname($dirRel));
                    if ($parentRel === '.') $parentRel = '';
                    if (!isset($dirs[$parentRel])) {
                        $parentAbs = ($parentRel === '') ? $rootReal : ($rootReal . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $parentRel));
                        $dirs[$parentRel] = [
                            'm' => safe_filemtime($parentAbs),
                            'd' => [],
                            'f' => [],
                            'ds' => 0,
                            'dfc' => 0,
                            't' => 0, 'fc' => 0, 'dc' => 0
                        ];
                    }
                    $dirs[$parentRel]['d'][] = basename(str_replace('\\', '/', $dirRel));
                }
            } else {
                $parentAbs = $info->getPath();
                $parentRel = normalize_rel(abs_to_rel($rootReal, $parentAbs));

                if (!isset($dirs[$parentRel])) {
                    $dirs[$parentRel] = [
                        'm' => safe_filemtime($parentAbs),
                        'd' => [],
                        'f' => [],
                        'ds' => 0,
                        'dfc' => 0,
                        't' => 0, 'fc' => 0, 'dc' => 0
                    ];
                }

                $size = (int)$info->getSize();
                $mtime = (int)$info->getMTime();
                $name = $info->getFilename();
                $fileRel = normalize_rel($rel);

                $dirs[$parentRel]['f'][] = [$name, $size, $mtime];
                $dirs[$parentRel]['ds'] += $size;
                $dirs[$parentRel]['dfc']++;

                $pqFiles->insert([$fileRel, $size, $mtime], -$size);
                if ($pqFiles->count() > $topFilesN) $pqFiles->extract();
            }
        } catch (Throwable $e) {
            continue;
        }
    }

    $keys = array_keys($dirs);
    usort($keys, function($a, $b){
        $da = ($a === '') ? 0 : (substr_count($a, '/') + 1);
        $db = ($b === '') ? 0 : (substr_count($b, '/') + 1);
        if ($da === $db) return strcmp($b, $a);
        return $db <=> $da;
    });

    foreach ($keys as $dirRel) {
        $directSize  = (int)$dirs[$dirRel]['ds'];
        $directFiles = (int)$dirs[$dirRel]['dfc'];

        $childTotalSize = 0;
        $childFileCount = 0;
        $childDirCount  = 0;

        $childNames = $dirs[$dirRel]['d'];
        if (count($childNames) > 1) {
            $childNames = array_values(array_unique($childNames));
            $dirs[$dirRel]['d'] = $childNames;
        }

        foreach ($childNames as $childName) {
            $childRel = ($dirRel === '') ? $childName : ($dirRel . '/' . $childName);
            if (!isset($dirs[$childRel])) continue;

            $childTotalSize += (int)$dirs[$childRel]['t'];
            $childFileCount += (int)$dirs[$childRel]['fc'];
            $childDirCount  += (int)$dirs[$childRel]['dc'];
        }

        $dirs[$dirRel]['t']  = $directSize + $childTotalSize;
        $dirs[$dirRel]['fc'] = $directFiles + $childFileCount;
        $dirs[$dirRel]['dc'] = count($childNames) + $childDirCount;
    }

    $pqDirs = new SplPriorityQueue();
    $pqDirs->setExtractFlags(SplPriorityQueue::EXTR_BOTH);

    foreach ($dirs as $dirRel => $d) {
        if ($dirRel === '') continue;
        $size = (int)$d['t'];
        $mtime = (int)$d['m'];
        $dc = (int)$d['dc'];
        $fc = (int)$d['fc'];

        $pqDirs->insert([$dirRel, $size, $mtime, $dc, $fc], -$size);
        if ($pqDirs->count() > $topDirsN) $pqDirs->extract();
    }

    $topFiles = [];
    $cloneF = clone $pqFiles;
    while (!$cloneF->isEmpty()) {
        $x = $cloneF->extract();
        if (isset($x['data']) && is_array($x['data'])) $topFiles[] = $x['data'];
    }
    usort($topFiles, fn($a,$b)=> ((int)($b[1]??0) <=> (int)($a[1]??0)) ?: strcmp((string)$a[0], (string)$b[0]));

    $topDirs = [];
    $cloneD = clone $pqDirs;
    while (!$cloneD->isEmpty()) {
        $x = $cloneD->extract();
        if (isset($x['data']) && is_array($x['data'])) $topDirs[] = $x['data'];
    }
    usort($topDirs, fn($a,$b)=> ((int)($b[1]??0) <=> (int)($a[1]??0)) ?: strcmp((string)$a[0], (string)$b[0]));

    foreach ($dirs as $k => $v) unset($dirs[$k]['ds'], $dirs[$k]['dfc']);

    $durationMs = (int)round((microtime(true) - $t0) * 1000);
    $peakMem = (int)memory_get_peak_usage(true);

    return [
        'app' => ['name' => $GLOBALS['APP_NAME'], 'version' => $GLOBALS['APP_VERSION']],
        'root' => $rootReal,
        'root_hash' => sha1($rootReal),
        'scanned_at' => $scannedAt,
        'scan_duration_ms' => $durationMs,
        'scan_peak_memory_bytes' => $peakMem,
        'scan_memory_limit_bytes' => $memLimit,
        'php_version' => PHP_VERSION,
        'dirs' => $dirs,
        'top_files' => $topFiles,
        'top_dirs' => $topDirs,
        'stats' => [
            'root_total_size' => (int)($dirs['']['t'] ?? 0),
            'root_file_count' => (int)($dirs['']['fc'] ?? 0),
            'root_dir_count'  => (int)($dirs['']['dc'] ?? 0)
        ]
    ];
}

// -------------------------- API assembly --------------------------
function build_items_for_dir(array $cache, string $rel): array {
    $dirs = $cache['dirs'] ?? [];
    if (!is_array($dirs)) return ['dir' => null, 'items' => []];

    if (!isset($dirs[$rel])) $rel = '';
    $dir = $dirs[$rel] ?? null;
    if (!is_array($dir)) return ['dir' => null, 'items' => []];

    $parentTotal = (int)($dir['t'] ?? 0);
    $items = [];

    $childNames = $dir['d'] ?? [];
    if (is_array($childNames) && count($childNames) > 1) $childNames = array_values(array_unique($childNames));

    foreach ($childNames as $childName) {
        if (!is_string($childName) || $childName === '') continue;
        $childRel = ($rel === '') ? $childName : ($rel . '/' . $childName);
        $child = $dirs[$childRel] ?? null;

        $size = is_array($child) ? (int)($child['t'] ?? 0) : 0;
        $mtime = is_array($child) ? (int)($child['m'] ?? 0) : 0;
        $dc = is_array($child) ? (int)($child['dc'] ?? 0) : 0;
        $fc = is_array($child) ? (int)($child['fc'] ?? 0) : 0;

        $percent = ($parentTotal > 0) ? ($size / $parentTotal) : 0.0;

        $items[] = [
            'type' => 'dir',
            'name' => $childName,
            'size' => $size,
            'percent' => $percent,
            'mtime' => $mtime,
            'dir_count' => $dc,
            'file_count' => $fc,
            'rel_path' => $childRel
        ];
    }

    $files = $dir['f'] ?? [];
    if (is_array($files)) {
        foreach ($files as $row) {
            if (!is_array($row) || count($row) < 3) continue;
            $name = (string)$row[0];
            $size = (int)$row[1];
            $mtime = (int)$row[2];
            $fileRel = ($rel === '') ? $name : ($rel . '/' . $name);
            $percent = ($parentTotal > 0) ? ($size / $parentTotal) : 0.0;

            $items[] = [
                'type' => 'file',
                'name' => $name,
                'size' => $size,
                'percent' => $percent,
                'mtime' => $mtime,
                'dir_count' => 0,
                'file_count' => 0,
                'rel_path' => $fileRel
            ];
        }
    }

    usort($items, fn($a,$b)=> ((int)$b['size'] <=> (int)$a['size']) ?: strcmp((string)$a['name'], (string)$b['name']));
    return ['dir' => $dir, 'items' => $items];
}

function filter_top_by_prefix(array $top, string $prefixRel, int $limit): array {
    $out = [];
    $prefix = ($prefixRel === '') ? '' : ($prefixRel . '/');
    foreach ($top as $row) {
        if (!is_array($row) || !isset($row[0])) continue;
        $rel = (string)$row[0];
        if ($prefixRel === '' || starts_with($rel, $prefix)) {
            $out[] = $row;
            if (count($out) >= $limit) break;
        }
    }
    return $out;
}

// -------------------------- Request handling --------------------------
$rel = isset($_GET['p']) ? (string)$_GET['p'] : '';
[$CURRENT_DIR_ABS, $REL_PATH] = resolve_dir($ROOT_DIR, $rel);
$crumbs = build_breadcrumb($REL_PATH);

$PARENT_REL = '';
if ($REL_PATH !== '') {
    $p = normalize_rel(dirname($REL_PATH));
    $PARENT_REL = ($p === '.' ? '' : $p);
}

$action = isset($_GET['action']) ? (string)$_GET['action'] : '';
if ($action !== '') {
    if (!in_array($action, ['get','scan'], true)) {
        json_response(['ok' => false, 'error' => 'Ação inválida.'], 400);
    }

    $lock = lock_status($LOCK_FILE, $LOCK_STALE_SECONDS);
    if ($lock['exists'] && $lock['stale']) {
        @unlink($LOCK_FILE);
        $lock = lock_status($LOCK_FILE, $LOCK_STALE_SECONDS);
    }

    if ($action === 'get') {
        $csrf = get_csrf_token();
        $cache = read_cache($CACHE_FILE);

        if (!$cache) {
            json_response([
                'ok' => true,
                'exists' => false,
                'csrf' => $csrf,
                'root' => $ROOT_DIR,
                'root_hash' => $ROOT_HASH,
                'current_rel' => $REL_PATH,
                'parent_rel' => $PARENT_REL,
                'lock' => $lock,
                'initial_scan_pending' => true,
                'scan_in_progress' => (bool)$lock['exists'],
                'server' => [
                    'php_version' => PHP_VERSION,
                    'memory_limit_bytes' => get_memory_limit_bytes()
                ]
            ]);
        }

        $assembled = build_items_for_dir($cache, $REL_PATH);
        $dir = $assembled['dir'];
        $items = $assembled['items'];

        $scannedAt = (int)($cache['scanned_at'] ?? 0);
        $scanDuration = (int)($cache['scan_duration_ms'] ?? 0);
        $peakMem = (int)($cache['scan_peak_memory_bytes'] ?? 0);
        $memLimit = $cache['scan_memory_limit_bytes'] ?? get_memory_limit_bytes();
        $phpVer = (string)($cache['php_version'] ?? PHP_VERSION);

        $stats = $cache['stats'] ?? [
            'root_total_size' => (int)(($cache['dirs']['']['t'] ?? 0)),
            'root_file_count' => (int)(($cache['dirs']['']['fc'] ?? 0)),
            'root_dir_count'  => (int)(($cache['dirs']['']['dc'] ?? 0))
        ];

        $topFiles = $cache['top_files'] ?? [];
        $topDirs  = $cache['top_dirs'] ?? [];

        $topFilesCur = filter_top_by_prefix(is_array($topFiles) ? $topFiles : [], $REL_PATH, $GLOBALS['TOP_SHOW_N']);
        $topDirsCur  = filter_top_by_prefix(is_array($topDirs) ? $topDirs : [], $REL_PATH, $GLOBALS['TOP_SHOW_N']);

        $tfGlobal = [];
        $tfSlice = array_slice(is_array($topFiles) ? $topFiles : [], 0, $GLOBALS['TOP_SHOW_N']);
        foreach ($tfSlice as $row) {
            if (!is_array($row) || count($row) < 3) continue;
            $relp = (string)$row[0];
            $name = basename(str_replace('\\','/',$relp));
            $dirr = normalize_rel(dirname($relp));
            if ($dirr === '.') $dirr = '';
            $tfGlobal[] = ['rel_path' => $relp, 'name' => $name, 'dir_rel' => $dirr, 'size' => (int)$row[1], 'mtime' => (int)$row[2]];
        }

        $tfCurrent = [];
        foreach ($topFilesCur as $row) {
            if (!is_array($row) || count($row) < 3) continue;
            $relp = (string)$row[0];
            $name = basename(str_replace('\\','/',$relp));
            $dirr = normalize_rel(dirname($relp));
            if ($dirr === '.') $dirr = '';
            $tfCurrent[] = ['rel_path' => $relp, 'name' => $name, 'dir_rel' => $dirr, 'size' => (int)$row[1], 'mtime' => (int)$row[2]];
        }

        $tdGlobal = [];
        $tdSlice = array_slice(is_array($topDirs) ? $topDirs : [], 0, $GLOBALS['TOP_SHOW_N']);
        foreach ($tdSlice as $row) {
            if (!is_array($row) || count($row) < 5) continue;
            $relp = (string)$row[0];
            $name = basename(str_replace('\\','/',$relp));
            $tdGlobal[] = ['rel_path' => $relp, 'name' => $name, 'size' => (int)$row[1], 'mtime' => (int)$row[2], 'dir_count' => (int)$row[3], 'file_count' => (int)$row[4]];
        }

        $tdCurrent = [];
        foreach ($topDirsCur as $row) {
            if (!is_array($row) || count($row) < 5) continue;
            $relp = (string)$row[0];
            $name = basename(str_replace('\\','/',$relp));
            $tdCurrent[] = ['rel_path' => $relp, 'name' => $name, 'size' => (int)$row[1], 'mtime' => (int)$row[2], 'dir_count' => (int)$row[3], 'file_count' => (int)$row[4]];
        }

        json_response([
            'ok' => true,
            'exists' => true,
            'csrf' => $csrf,
            'app' => $cache['app'] ?? ['name'=>$GLOBALS['APP_NAME'],'version'=>$GLOBALS['APP_VERSION']],
            'root' => $cache['root'] ?? $ROOT_DIR,
            'root_hash' => $cache['root_hash'] ?? $ROOT_HASH,
            'scanned_at' => $scannedAt,
            'scan_duration_ms' => $scanDuration,
            'scan_peak_memory_bytes' => $peakMem,
            'scan_memory_limit_bytes' => $memLimit,
            'php_version' => $phpVer,
            'current_rel' => $REL_PATH,
            'parent_rel' => $PARENT_REL,
            'current' => [
                'total_size' => (int)($dir['t'] ?? 0),
                'file_count' => (int)($dir['fc'] ?? 0),
                'dir_count'  => (int)($dir['dc'] ?? 0),
                'mtime'      => (int)($dir['m'] ?? 0),
                'items'      => $items
            ],
            'stats' => $stats,
            'lock' => $lock,
            'initial_scan_pending' => ($scannedAt <= 0),
            'scan_in_progress' => (bool)$lock['exists'],
            'top_files_global' => $tfGlobal,
            'top_files_current' => $tfCurrent,
            'top_dirs_global' => $tdGlobal,
            'top_dirs_current' => $tdCurrent,
            'server' => [
                'memory_limit_bytes' => get_memory_limit_bytes()
            ]
        ]);
    }

    if ($action === 'scan') {
        require_csrf();

        $lock = lock_status($LOCK_FILE, $LOCK_STALE_SECONDS);
        if ($lock['exists'] && !$lock['stale']) {
            json_response(['ok' => false, 'error' => 'Uma varredura já está em andamento.'], 409);
        }

        // IMPORTANT FIX: do NOT exit inside try; release lock in finally, then respond.
        $fh = null;
        $payload = ['ok' => false, 'error' => 'Erro desconhecido.'];
        $status = 500;

        try {
            $fh = acquire_lock($LOCK_FILE, $LOCK_STALE_SECONDS);

            $data = scan_full_tree_slim(
                $ROOT_DIR,
                $CACHE_PREFIX,
                $SCRIPT_BASENAME,
                basename($CACHE_FILE),
                $LOCK_FILE,
                $TOP_FILES_N,
                $TOP_DIRS_N,
                $MEM_CHECK_EVERY,
                $MEM_ABORT_AT
            );

            write_cache_atomic($CACHE_FILE, $data);

            $payload = [
                'ok' => true,
                'scanned_at' => (int)$data['scanned_at'],
                'scan_duration_ms' => (int)$data['scan_duration_ms'],
                'scan_peak_memory_bytes' => (int)$data['scan_peak_memory_bytes'],
                'scan_memory_limit_bytes' => (int)$data['scan_memory_limit_bytes']
            ];
            $status = 200;
        } catch (Throwable $e) {
            $payload = ['ok' => false, 'error' => $e->getMessage()];
            $status = 500;
        } finally {
            if ($fh !== null) release_lock($fh, $LOCK_FILE);
            else @unlink($LOCK_FILE);
        }

        json_response($payload, $status);
    }
}

// -------------------------- HTML --------------------------
$csrfToken = get_csrf_token();
$cacheExists = is_file($CACHE_FILE);
$cacheMtime = $cacheExists ? safe_filemtime($CACHE_FILE) : 0;
$cacheAgeSec = $cacheMtime ? (time() - $cacheMtime) : 0;
?>
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?php echo h($APP_NAME); ?></title>

  <!-- Bootstrap -->
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.8/css/bootstrap.min.css" referrerpolicy="no-referrer">
  <!-- Bootstrap Icons -->
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/1.13.1/font/bootstrap-icons.min.css" referrerpolicy="no-referrer">

  <style>
    body { background: #f6f7fb; }
    .app-shell { border: 0; border-radius: 18px; box-shadow: 0 12px 28px rgba(0,0,0,.08); overflow: hidden; }
    .hero {
      background: linear-gradient(135deg, rgba(13,110,253,.12), rgba(25,135,84,.10));
      border-bottom: 1px solid rgba(0,0,0,.06);
    }
    .brand-pill {
      display:inline-flex; align-items:center; gap:.6rem;
      padding:.35rem .75rem; border-radius: 999px;
      background: rgba(255,255,255,.72);
      border: 1px solid rgba(0,0,0,.08);
    }
    .brand-pill .logo {
      width: 34px; height: 34px; border-radius: 12px;
      display:flex; align-items:center; justify-content:center;
      background: rgba(13,110,253,.10);
      border: 1px solid rgba(0,0,0,.06);
    }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    .muted { color: #6c757d; }

    .name-cell { position: relative; overflow: hidden; border-radius: .65rem; }
    .name-bar { position:absolute; inset:0 auto 0 0; width:0%; background: rgba(13,110,253,.14); }
    .name-content { position: relative; z-index: 1; padding: .45rem .55rem; }
    .truncate { max-width: 540px; }
    @media (max-width: 992px) { .truncate { max-width: 240px; } }

    .crumb-wrap {
      background: #fff;
      border: 1px solid rgba(0,0,0,.10);
      border-radius: 14px;
      padding: .6rem .75rem;
    }
    .breadcrumb { margin-bottom: 0; }
    .breadcrumb a { text-decoration: none; }

    #loadingOverlay { background: rgba(255,255,255,.82); backdrop-filter: blur(2px); }
    .footer-bar { border-top: 1px solid rgba(0,0,0,.08); }
    .stat-card { border:0; border-radius: 16px; box-shadow: 0 8px 18px rgba(0,0,0,.06); }

    .btn-icon { width: 38px; height: 38px; display:inline-flex; align-items:center; justify-content:center; }
    .table thead th { white-space: nowrap; }

    .stale-alert { max-width: 460px; }
  </style>
</head>

<body class="py-4">
<div class="container">
  <noscript>
    <div class="alert alert-warning">
      <strong>JavaScript</strong> é necessário para carregar a interface. / <strong>JavaScript</strong> is required to load the UI.
    </div>
  </noscript>

  <div class="card app-shell">
    <div class="hero p-4 p-lg-5">
      <div class="d-flex flex-column flex-lg-row justify-content-between align-items-start align-items-lg-center gap-3">
        <div class="w-100">
          <div class="brand-pill mb-3">
            <div class="logo"><i class="bi bi-filetype-php fs-4 text-primary"></i></div>
            <div class="lh-sm">
              <div class="fw-semibold"><?php echo h($APP_NAME); ?></div>
              <div class="small muted" data-i18n="subtitle"></div>
            </div>
          </div>

          <h1 class="h4 mb-2" data-i18n="title"></h1>

          <div class="small muted mb-1">
            <span data-i18n="root_label"></span>:
            <span class="mono"><?php echo h($ROOT_DIR); ?></span>
          </div>

          <div class="small" id="scanInfo">
            <span class="text-secondary" data-i18n="loading_cache"></span>
          </div>
        </div>

        <div class="d-flex flex-column gap-2 align-items-stretch">
          <div class="d-flex gap-2 justify-content-end">
            <button class="btn btn-primary" id="btnScan">
              <i class="bi bi-play-fill me-1"></i><span data-i18n="btn_scan"></span>
            </button>
            <button class="btn btn-outline-primary" id="btnRescan">
              <i class="bi bi-arrow-clockwise me-1"></i><span data-i18n="btn_rescan"></span>
            </button>
          </div>

          <div id="lockAlert" class="alert alert-warning py-2 px-3 mb-0 small d-none">
            <i class="bi bi-hourglass-split me-1"></i><span id="lockText">—</span>
          </div>

          <div id="staleAlert" class="alert alert-warning py-2 px-3 mb-0 small stale-alert d-none">
            <i class="bi bi-exclamation-triangle me-1"></i><span id="staleText">—</span>
          </div>
        </div>
      </div>

      <div class="row g-3 mt-4">
        <div class="col-12 col-md-4">
          <div class="card stat-card">
            <div class="card-body">
              <div class="small muted" data-i18n="stat_total"></div>
              <div class="h5 mb-0" id="statTotal">—</div>
            </div>
          </div>
        </div>
        <div class="col-6 col-md-4">
          <div class="card stat-card">
            <div class="card-body">
              <div class="small muted" data-i18n="stat_files"></div>
              <div class="h5 mb-0" id="statFiles">—</div>
            </div>
          </div>
        </div>
        <div class="col-6 col-md-4">
          <div class="card stat-card">
            <div class="card-body">
              <div class="small muted" data-i18n="stat_dirs"></div>
              <div class="h5 mb-0" id="statDirs">—</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="p-4 p-lg-5">
      <ul class="nav nav-tabs" role="tablist">
        <li class="nav-item" role="presentation">
          <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#tab-items" type="button" role="tab">
            <i class="bi bi-folder2-open me-1"></i><span data-i18n="tab_items"></span>
          </button>
        </li>
        <li class="nav-item" role="presentation">
          <button class="nav-link" data-bs-toggle="tab" data-bs-target="#tab-topfiles" type="button" role="tab">
            <i class="bi bi-trophy me-1"></i><span data-i18n="tab_top_files"></span>
          </button>
        </li>
        <li class="nav-item" role="presentation">
          <button class="nav-link" data-bs-toggle="tab" data-bs-target="#tab-topdirs" type="button" role="tab">
            <i class="bi bi-trophy me-1"></i><span data-i18n="tab_top_dirs"></span>
          </button>
        </li>
        <li class="nav-item" role="presentation">
          <button class="nav-link" data-bs-toggle="tab" data-bs-target="#tab-selected" type="button" role="tab">
            <i class="bi bi-bookmark-star me-1"></i><span data-i18n="tab_selected"></span>
            <span class="badge text-bg-light text-secondary border ms-2" id="selBadge">0</span>
          </button>
        </li>
        <li class="nav-item" role="presentation">
          <button class="nav-link" data-bs-toggle="tab" data-bs-target="#tab-about" type="button" role="tab">
            <i class="bi bi-info-circle me-1"></i><span data-i18n="tab_about"></span>
          </button>
        </li>
      </ul>

      <div class="tab-content pt-3">
        <div class="tab-pane fade show active" id="tab-items" role="tabpanel">
          <div class="d-flex flex-column flex-lg-row align-items-start align-items-lg-center justify-content-between gap-2 mb-3">
            <div class="crumb-wrap w-100">
              <nav aria-label="breadcrumb">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="?"><i class="bi bi-house-door me-1"></i><span data-i18n="breadcrumb_root"></span></a>
                  </li>
                  <?php foreach ($crumbs as $c): ?>
                    <li class="breadcrumb-item">
                      <a href="?p=<?php echo h($c['p']); ?>"><?php echo h($c['label']); ?></a>
                    </li>
                  <?php endforeach; ?>
                  <li class="breadcrumb-item active" aria-current="page">
                    <span class="mono"><?php echo $REL_PATH === '' ? '(root)' : h(basename(str_replace('\\','/',$REL_PATH))); ?></span>
                  </li>
                </ol>
              </nav>
            </div>

            <div class="d-flex gap-2">
              <?php if ($REL_PATH !== ''): ?>
                <a class="btn btn-outline-secondary btn-icon" href="?p=<?php echo h($PARENT_REL); ?>" id="btnUp" title="Up">
                  <i class="bi bi-arrow-up"></i>
                </a>
              <?php else: ?>
                <button class="btn btn-outline-secondary btn-icon" disabled title="Up"><i class="bi bi-arrow-up"></i></button>
              <?php endif; ?>
            </div>
          </div>

          <div class="d-flex flex-column flex-lg-row gap-2 align-items-start align-items-lg-center justify-content-between mb-3">
            <div class="small muted" data-i18n="items_hint"></div>

            <div class="d-flex flex-column flex-sm-row gap-2 align-items-stretch align-items-sm-center">
              <div class="input-group" style="max-width: 440px;">
                <span class="input-group-text"><i class="bi bi-search"></i></span>
                <input class="form-control" id="filterInput" data-i18n-placeholder="filter_placeholder" placeholder="">
                <button class="btn btn-outline-secondary" id="btnClearFilter" title="Clear"><i class="bi bi-x-lg"></i></button>
              </div>

              <div class="input-group" style="width: 170px;">
                <span class="input-group-text"><i class="bi bi-list"></i></span>
                <select class="form-select" id="pageSizeSelect">
                  <option value="50">50</option>
                  <option value="100">100</option>
                  <option value="<?php echo (int)$DEFAULT_PAGE_SIZE; ?>" selected><?php echo (int)$DEFAULT_PAGE_SIZE; ?></option>
                  <option value="250">250</option>
                  <option value="500">500</option>
                </select>
              </div>
            </div>
          </div>

          <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
              <thead class="table-light">
              <tr>
                <th style="min-width: 420px;" data-i18n="th_name"></th>
                <th class="text-center" style="width: 70px;" data-i18n="th_add"></th>
                <th data-i18n="th_size"></th>
                <th data-i18n="th_percent"></th>
                <th data-i18n="th_mtime"></th>
                <th data-i18n="th_counts"></th>
              </tr>
              </thead>
              <tbody id="tbodyItems">
              <tr>
                <td colspan="6" class="text-center py-5 text-secondary" data-i18n="no_data_yet"></td>
              </tr>
              </tbody>
            </table>
          </div>

          <div class="d-flex flex-column flex-md-row justify-content-between align-items-start align-items-md-center gap-2 mt-3">
            <div class="small muted" id="itemsInfo">—</div>
            <div class="d-flex align-items-center gap-2">
              <button class="btn btn-outline-secondary btn-sm" id="btnPrev"><i class="bi bi-chevron-left"></i></button>
              <span class="small muted" id="pageInfo">—</span>
              <button class="btn btn-outline-secondary btn-sm" id="btnNext"><i class="bi bi-chevron-right"></i></button>
            </div>
          </div>
        </div>

        <div class="tab-pane fade" id="tab-topfiles" role="tabpanel">
          <div class="d-flex flex-column flex-lg-row gap-2 align-items-start align-items-lg-center justify-content-between mb-3">
            <div class="small muted" data-i18n="top_files_hint"></div>
            <div class="btn-group" role="group" aria-label="Scope top files">
              <input type="radio" class="btn-check" name="scopeFiles" id="scopeFilesRoot" checked>
              <label class="btn btn-outline-primary" for="scopeFilesRoot" data-i18n="scope_root"></label>
              <input type="radio" class="btn-check" name="scopeFiles" id="scopeFilesCur">
              <label class="btn btn-outline-primary" for="scopeFilesCur" data-i18n="scope_current"></label>
            </div>
          </div>

          <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
              <thead class="table-light">
              <tr>
                <th style="min-width: 520px;" data-i18n="th_file"></th>
                <th class="text-center" style="width: 70px;" data-i18n="th_add"></th>
                <th data-i18n="th_size"></th>
                <th data-i18n="th_mtime"></th>
              </tr>
              </thead>
              <tbody id="tbodyTopFiles"></tbody>
            </table>
          </div>
        </div>

        <div class="tab-pane fade" id="tab-topdirs" role="tabpanel">
          <div class="d-flex flex-column flex-lg-row gap-2 align-items-start align-items-lg-center justify-content-between mb-3">
            <div class="small muted" data-i18n="top_dirs_hint"></div>
            <div class="btn-group" role="group" aria-label="Scope top dirs">
              <input type="radio" class="btn-check" name="scopeDirs" id="scopeDirsRoot" checked>
              <label class="btn btn-outline-primary" for="scopeDirsRoot" data-i18n="scope_root"></label>
              <input type="radio" class="btn-check" name="scopeDirs" id="scopeDirsCur">
              <label class="btn btn-outline-primary" for="scopeDirsCur" data-i18n="scope_current"></label>
            </div>
          </div>

          <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
              <thead class="table-light">
              <tr>
                <th style="min-width: 520px;" data-i18n="th_folder"></th>
                <th class="text-center" style="width: 70px;" data-i18n="th_add"></th>
                <th data-i18n="th_size"></th>
                <th data-i18n="th_mtime"></th>
                <th data-i18n="th_counts_short"></th>
              </tr>
              </thead>
              <tbody id="tbodyTopDirs"></tbody>
            </table>
          </div>
        </div>

        <div class="tab-pane fade" id="tab-selected" role="tabpanel">
          <div class="d-flex flex-column flex-lg-row gap-2 align-items-start align-items-lg-center justify-content-between mb-3">
            <div class="small muted" data-i18n="sel_hint"></div>
            <div class="d-flex gap-2">
              <button class="btn btn-outline-secondary btn-sm" id="btnExport">
                <i class="bi bi-download me-1"></i><span data-i18n="export"></span>
              </button>
              <button class="btn btn-outline-danger btn-sm" id="btnClearSel">
                <i class="bi bi-trash3 me-1"></i><span data-i18n="clear_selection"></span>
              </button>
            </div>
          </div>

          <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
              <thead class="table-light">
              <tr>
                <th style="min-width: 520px;" data-i18n="th_item"></th>
                <th data-i18n="th_type"></th>
                <th data-i18n="th_size"></th>
                <th data-i18n="th_mtime"></th>
                <th class="text-center" style="width: 70px;" data-i18n="th_remove"></th>
              </tr>
              </thead>
              <tbody id="tbodySelected"></tbody>
            </table>
          </div>

          <div class="mt-3 small muted" id="selTotals">—</div>
        </div>

        <div class="tab-pane fade" id="tab-about" role="tabpanel">
          <div class="row g-3">
            <div class="col-12 col-lg-7">
              <div class="card stat-card">
                <div class="card-body p-4">
                  <h5 class="mb-2" data-i18n="about_title"></h5>
                  <p class="text-secondary mb-0" data-i18n="about_intro"></p>
                </div>
              </div>

              <div class="card stat-card mt-3">
                <div class="card-body p-4">
                  <h6 class="mb-3" data-i18n="about_how_title"></h6>
                  <ul class="mb-0">
                    <li data-i18n="about_how_1"></li>
                    <li data-i18n="about_how_2"></li>
                    <li data-i18n="about_how_3"></li>
                    <li data-i18n="about_how_4"></li>
                    <li data-i18n="about_how_5"></li>
                  </ul>
                </div>
              </div>

              <div class="card stat-card mt-3">
                <div class="card-body p-4">
                  <h6 class="mb-3" data-i18n="about_storage_title"></h6>
                  <ul class="mb-0">
                    <li data-i18n="about_storage_1"></li>
                    <li data-i18n="about_storage_2"></li>
                  </ul>
                </div>
              </div>
            </div>

            <div class="col-12 col-lg-5">
              <div class="card stat-card">
                <div class="card-body p-4">
                  <div class="d-flex justify-content-between align-items-center mb-3">
                    <h6 class="mb-0" data-i18n="diag_title"></h6>
                    <span class="badge text-bg-light text-secondary border"><i class="bi bi-activity me-1"></i><span data-i18n="diag_live"></span></span>
                  </div>

                  <div class="list-group list-group-flush">
                    <div class="list-group-item d-flex justify-content-between align-items-center">
                      <span data-i18n="diag_cache"></span><span id="diagCache">—</span>
                    </div>
                    <div class="list-group-item d-flex justify-content-between align-items-center">
                      <span data-i18n="diag_lock"></span><span id="diagLock">—</span>
                    </div>
                    <div class="list-group-item d-flex justify-content-between align-items-center">
                      <span data-i18n="diag_last_scan"></span><span id="diagLastScan">—</span>
                    </div>
                    <div class="list-group-item d-flex justify-content-between align-items-center">
                      <span data-i18n="diag_duration"></span><span id="diagDuration">—</span>
                    </div>
                    <div class="list-group-item d-flex justify-content-between align-items-center">
                      <span data-i18n="diag_cache_age"></span><span id="diagCacheAge">—</span>
                    </div>
                    <div class="list-group-item d-flex justify-content-between align-items-center">
                      <span data-i18n="diag_current"></span><span id="diagCurrent" class="mono text-truncate d-inline-block" style="max-width: 220px;">—</span>
                    </div>
                    <div class="list-group-item d-flex justify-content-between align-items-center">
                      <span data-i18n="diag_root_total"></span><span id="diagRootTotal">—</span>
                    </div>
                    <div class="list-group-item d-flex justify-content-between align-items-center">
                      <span data-i18n="diag_selection"></span><span id="diagSel">—</span>
                    </div>
                    <div class="list-group-item d-flex justify-content-between align-items-center">
                      <span>PHP</span><span id="diagPhp" class="mono">—</span>
                    </div>
                    <div class="list-group-item d-flex justify-content-between align-items-center">
                      <span data-i18n="diag_memlimit"></span><span id="diagMemLimit">—</span>
                    </div>
                    <div class="list-group-item d-flex justify-content-between align-items-center">
                      <span data-i18n="diag_peak"></span><span id="diagPeak">—</span>
                    </div>
                  </div>

                  <div class="alert alert-info mt-3 mb-0 small">
                    <i class="bi bi-shield-check me-1"></i>
                    <span data-i18n="diag_tip"></span>
                  </div>
                </div>
              </div>

              <div class="card stat-card mt-3">
                <div class="card-body p-4">
                  <div class="small muted"><span class="mono"><?php echo h($APP_NAME); ?></span> v<?php echo h($APP_VERSION); ?></div>
                  <div class="small muted mt-1">
                    Author: Victor Benincasa • <a href="https://github.com/vbenincasa/phpDiskTree" target="_blank">https://github.com/vbenincasa/phpDiskTree</a>
                  </div>
                </div>
              </div>

            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="footer-bar p-3 px-lg-5 d-flex flex-column flex-md-row justify-content-between align-items-start align-items-md-center gap-2">
      <div class="small muted">
        <span data-i18n="cache_saved"></span>
        <span class="mono"><?php echo h(basename($CACHE_FILE)); ?></span>
        • <span data-i18n="cache_update"></span>
      </div>

      <div class="d-flex align-items-center gap-2">
        <span class="small text-secondary"><i class="bi bi-translate me-1"></i><span data-i18n="language"></span>:</span>
        <select class="form-select form-select-sm" id="langSelect" style="width: 170px;">
          <option value="pt">Português</option>
          <option value="en">English</option>
        </select>
      </div>
    </div>
  </div>
</div>

<div id="loadingOverlay" class="position-fixed top-0 start-0 w-100 h-100 d-none" style="z-index: 1050;">
  <div class="d-flex flex-column justify-content-center align-items-center h-100">
    <div class="spinner-border" role="status"></div>
    <div class="mt-3 fw-semibold" data-i18n="scan_running"></div>
    <div class="mt-1 small muted" data-i18n="scan_running_hint"></div>
  </div>
</div>

<div class="position-fixed bottom-0 end-0 p-3" style="z-index: 1060">
  <div id="toast" class="toast align-items-center text-bg-secondary border-0" role="alert" aria-live="assertive" aria-atomic="true">
    <div class="d-flex">
      <div class="toast-body" id="toastBody">—</div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
    </div>
  </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.8/js/bootstrap.bundle.min.js" referrerpolicy="no-referrer"></script>

<script>
  const CURRENT_REL = <?php echo json_encode($REL_PATH, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); ?>;
  const ROOT_HASH   = <?php echo json_encode($ROOT_HASH, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); ?>;
  const CSRF_TOKEN  = <?php echo json_encode($csrfToken, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); ?>;
  const CACHE_STALE_SECONDS = <?php echo (int)$CACHE_STALE_SECONDS; ?>;

  const LS_LANG = "phpdisktree_lang_v1";
  const LS_SEL  = "phpdisktree_selection_v1_" + ROOT_HASH;

  const STR = {
    pt: {
      subtitle: "Disk usage explorer",
      title: "Consumo de espaço em disco",
      root_label: "Raiz",
      loading_cache: "Carregando status do cache…",
      btn_scan: "Iniciar varredura",
      btn_rescan: "Atualizar varredura",
      stat_total: "Tamanho total (raiz)",
      stat_files: "Arquivos (raiz)",
      stat_dirs: "Subpastas (raiz)",
      tab_items: "Itens da pasta",
      tab_top_files: "Top maiores arquivos",
      tab_top_dirs: "Top maiores pastas",
      tab_selected: "Arquivos/pastas selecionados",
      tab_about: "Sobre",
      breadcrumb_root: "Raiz",
      items_hint: "Listagem em ordem decrescente de tamanho, baseada no cache da varredura completa.",
      filter_placeholder: "Filtrar por nome…",
      th_name: "Nome",
      th_add: "Seleção",
      th_size: "Tamanho",
      th_percent: "Percentual",
      th_mtime: "Modificado em",
      th_counts: "Total subpastas/arquivos",
      th_counts_short: "Conteúdo",
      th_file: "Arquivo",
      th_folder: "Pasta",
      th_item: "Item",
      th_type: "Tipo",
      th_remove: "Remover",
      top_files_hint: "Maiores arquivos encontrados na varredura completa.",
      top_dirs_hint: "Maiores pastas encontradas na varredura completa.",
      scope_root: "Raiz",
      scope_current: "Pasta atual",
      sel_hint: "Itens marcados pelo usuário durante a navegação (armazenado no navegador).",
      export: "Exportar (.txt)",
      clear_selection: "Limpar seleção",
      cache_saved: "Cache salvo em",
      cache_update: "Para atualizar, use “Atualizar varredura”.",
      language: "Idioma",
      scan_running: "Varredura completa em andamento…",
      scan_running_hint: "Pode demorar em discos com muitos arquivos.",
      no_data_yet: "Sem dados ainda. Clique em Iniciar varredura.",
      no_items_found: "Nenhum item encontrado.",
      already_selected: "Já selecionado",
      added: "Adicionar à seleção",
      removed: "Removido da seleção.",
      added_ok: "Adicionado à seleção.",
      exists: "Já estava na seleção.",
      confirm_clear: "Tem certeza que deseja limpar toda a seleção?",
      exported: "Exportação gerada.",
      type_file: "Arquivo",
      type_dir: "Pasta",
      remove: "Remover",
      page_info: "Página {page} de {pages}",
      showing_info: "Mostrando {from}-{to} de {total} itens.",
      badge_no_cache: "Sem cache",
      cache_missing: "Sem cache. Clique em Iniciar varredura para varrer toda a raiz.",
      cache_loaded: "Cache carregado",
      scan_complete_at: "Varredura completa em",
      stale_cache: "Seu cache tem mais de 12h (≈ {hours}h). Recomendamos atualizar a varredura.",
      scan_lock_msg: "Varredura em andamento (≈ {mins} min). Aguarde terminar.",
      no_top_yet: "Sem dados ainda. Faça a varredura.",
      folder_label_root: "(raiz)",
      sel_item_singular: "item",
      sel_item_plural: "itens",

      about_title: "Sobre o phpDiskTree",
      about_intro: "Explorador de uso de disco com varredura completa e cache persistente, feito para identificar rapidamente o que mais ocupa espaço.",
      about_how_title: "Como funciona",
      about_how_1: "Clique em “Iniciar varredura” para varrer recursivamente toda a raiz.",
      about_how_2: "O resultado é salvo em cache (JSON) e reutilizado até você atualizar.",
      about_how_3: "A aba “Itens da pasta” lista apenas filhos imediatos da pasta atual, ordenados por tamanho.",
      about_how_4: "As abas “Top maiores” ajudam a achar rapidamente os maiores candidatos a limpeza.",
      about_how_5: "Há lockfile e CSRF para reduzir riscos de abuso e concorrência.",
      about_storage_title: "Seleção e exportação",
      about_storage_1: "A seleção fica no navegador (localStorage) e é isolada por instalação (hash da raiz).",
      about_storage_2: "A exportação gera um .txt com um item por linha: “caminho + tamanho”.",

      diag_title: "Diagnóstico",
      diag_live: "Ao vivo",
      diag_cache: "Cache",
      diag_lock: "Lock",
      diag_last_scan: "Última varredura",
      diag_duration: "Duração",
      diag_cache_age: "Idade do cache",
      diag_current: "Pasta atual",
      diag_root_total: "Total da raiz",
      diag_selection: "Selecionados",
      diag_memlimit: "Memory limit",
      diag_peak: "Peak (scan)",
      diag_tip: "Recomendação: não exponha publicamente sem autenticação (o script revela nomes e tamanhos)."
    },
    en: {
      subtitle: "Disk usage explorer",
      title: "Disk space usage",
      root_label: "Root",
      loading_cache: "Loading cache status…",
      btn_scan: "Start scan",
      btn_rescan: "Rescan",
      stat_total: "Total size (root)",
      stat_files: "Files (root)",
      stat_dirs: "Folders (root)",
      tab_items: "Folder items",
      tab_top_files: "Top largest files",
      tab_top_dirs: "Top largest folders",
      tab_selected: "Selected files/folders",
      tab_about: "About",
      breadcrumb_root: "Root",
      items_hint: "Sorted by size descending, based on the full-scan cache.",
      filter_placeholder: "Filter by name…",
      th_name: "Name",
      th_add: "Selection",
      th_size: "Size",
      th_percent: "Percent",
      th_mtime: "Modified",
      th_counts: "Total subfolders/files (if folder)",
      th_counts_short: "Contents",
      th_file: "File",
      th_folder: "Folder",
      th_item: "Item",
      th_type: "Type",
      th_remove: "Remove",
      top_files_hint: "Largest files found in the full scan.",
      top_dirs_hint: "Largest folders found in the full scan.",
      scope_root: "Root",
      scope_current: "Current folder",
      sel_hint: "Items marked by the user while browsing (stored in your browser).",
      export: "Export (.txt)",
      clear_selection: "Clear selection",
      cache_saved: "Cache saved in",
      cache_update: "To refresh, click “Rescan”.",
      language: "Language",
      scan_running: "Full scan running…",
      scan_running_hint: "This can take a while on large disks.",
      no_data_yet: "No data yet. Click Start scan.",
      no_items_found: "No items found.",
      already_selected: "Already selected",
      added: "Add to selection",
      removed: "Removed from selection.",
      added_ok: "Added to selection.",
      exists: "Already in selection.",
      confirm_clear: "Are you sure you want to clear the whole selection?",
      exported: "Export generated.",
      type_file: "File",
      type_dir: "Folder",
      remove: "Remove",
      page_info: "Page {page} of {pages}",
      showing_info: "Showing {from}-{to} of {total} items.",
      badge_no_cache: "No cache",
      cache_missing: "No cache. Click Start scan to scan the entire root.",
      cache_loaded: "Cache loaded",
      scan_complete_at: "Full scan at",
      stale_cache: "Your cache is older than 12h (≈ {hours}h). We recommend rescanning.",
      scan_lock_msg: "Scan in progress (≈ {mins} min). Please wait.",
      no_top_yet: "No data yet. Run the scan.",
      folder_label_root: "(root)",
      sel_item_singular: "item",
      sel_item_plural: "items",

      about_title: "About phpDiskTree",
      about_intro: "A disk-usage explorer with full scan + persistent cache, built to quickly identify what consumes the most space.",
      about_how_title: "How it works",
      about_how_1: "Click “Start scan” to recursively scan the entire root.",
      about_how_2: "Results are saved in a JSON cache and reused until you rescan.",
      about_how_3: "“Folder items” lists only direct children of the current folder, sorted by size.",
      about_how_4: "“Top largest” tabs help you find the biggest cleanup candidates quickly.",
      about_how_5: "Lockfile and CSRF reduce concurrency and abuse risks.",
      about_storage_title: "Selection and export",
      about_storage_1: "Selection is stored in your browser (localStorage) and isolated per installation (root hash).",
      about_storage_2: "Export generates a .txt with one item per line: “path + size”.",

      diag_title: "Diagnostics",
      diag_live: "Live",
      diag_cache: "Cache",
      diag_lock: "Lock",
      diag_last_scan: "Last scan",
      diag_duration: "Duration",
      diag_cache_age: "Cache age",
      diag_current: "Current folder",
      diag_root_total: "Root total",
      diag_selection: "Selected",
      diag_memlimit: "Memory limit",
      diag_peak: "Peak (scan)",
      diag_tip: "Recommendation: don’t expose publicly without authentication (this reveals names and sizes)."
    }
  };

  let lang = "pt";
  let LOCALE = "pt-BR";
  let nfInt, nfDec2;

  function detectLang() {
    const saved = localStorage.getItem(LS_LANG);
    if (saved === "pt" || saved === "en") return saved;
    const nav = (navigator.language || "en").toLowerCase();
    return nav.startsWith("pt") ? "pt" : "en";
  }

  function setLocale(l) {
    lang = (l === "en") ? "en" : "pt";
    LOCALE = (lang === "en") ? "en-US" : "pt-BR";
    nfInt = new Intl.NumberFormat(LOCALE);
    nfDec2 = new Intl.NumberFormat(LOCALE, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }

  function t(key) { return (STR[lang] && STR[lang][key]) ? STR[lang][key] : key; }

  function applyI18n() {
    document.documentElement.lang = (lang === "en") ? "en" : "pt-BR";
    document.querySelectorAll("[data-i18n]").forEach(el => el.textContent = t(el.dataset.i18n));
    document.querySelectorAll("[data-i18n-placeholder]").forEach(el => el.placeholder = t(el.dataset.i18nPlaceholder));
  }

  const overlay = document.getElementById('loadingOverlay');
  const btnScan = document.getElementById('btnScan');
  const btnRescan = document.getElementById('btnRescan');
  const scanInfo = document.getElementById('scanInfo');

  const lockAlert = document.getElementById('lockAlert');
  const lockText  = document.getElementById('lockText');
  const staleAlert= document.getElementById('staleAlert');
  const staleText = document.getElementById('staleText');

  const statTotal = document.getElementById('statTotal');
  const statFiles = document.getElementById('statFiles');
  const statDirs  = document.getElementById('statDirs');

  const filterInput = document.getElementById('filterInput');
  const btnClearFilter = document.getElementById('btnClearFilter');
  const pageSizeSelect = document.getElementById('pageSizeSelect');
  const btnPrev = document.getElementById('btnPrev');
  const btnNext = document.getElementById('btnNext');
  const pageInfo = document.getElementById('pageInfo');
  const itemsInfo = document.getElementById('itemsInfo');

  const tbodyItems = document.getElementById('tbodyItems');
  const tbodyTopFiles = document.getElementById('tbodyTopFiles');
  const tbodyTopDirs = document.getElementById('tbodyTopDirs');

  const selBadge = document.getElementById('selBadge');
  const tbodySelected = document.getElementById('tbodySelected');
  const selTotals = document.getElementById('selTotals');
  const btnExport = document.getElementById('btnExport');
  const btnClearSel = document.getElementById('btnClearSel');

  const langSelect = document.getElementById('langSelect');

  const scopeFilesRoot = document.getElementById('scopeFilesRoot');
  const scopeFilesCur  = document.getElementById('scopeFilesCur');
  const scopeDirsRoot  = document.getElementById('scopeDirsRoot');
  const scopeDirsCur   = document.getElementById('scopeDirsCur');

  const diagCache = document.getElementById('diagCache');
  const diagLock  = document.getElementById('diagLock');
  const diagLastScan = document.getElementById('diagLastScan');
  const diagDuration = document.getElementById('diagDuration');
  const diagCacheAge = document.getElementById('diagCacheAge');
  const diagCurrent  = document.getElementById('diagCurrent');
  const diagRootTotal= document.getElementById('diagRootTotal');
  const diagSel      = document.getElementById('diagSel');
  const diagPhp      = document.getElementById('diagPhp');
  const diagMemLimit = document.getElementById('diagMemLimit');
  const diagPeak     = document.getElementById('diagPeak');

  const toastEl = document.getElementById('toast');
  const toastBody = document.getElementById('toastBody');
  const toast = new bootstrap.Toast(toastEl, { delay: 6000 });
  function showToast(msg) { toastBody.textContent = msg; toast.show(); }

  let lastItems = [];
  let scannedAt = 0;
  let scanDurationMs = 0;
  let peakMemBytes = 0;
  let memLimitBytes = -1;
  let phpVersion = '';
  let rootStats = { root_total_size: 0, root_file_count: 0, root_dir_count: 0 };
  let lockState = { exists:false, stale:false, age_sec:0 };

  let topFilesRoot = [];
  let topFilesCur = [];
  let topDirsRoot = [];
  let topDirsCur = [];

  let pageSize = parseInt(pageSizeSelect.value || "150", 10);
  let currentPage = 1;

  function formatBytes(bytes) {
    bytes = Number(bytes || 0);
    if (!isFinite(bytes) || bytes <= 0) return "0 B";
    const units = ["B","KB","MB","GB","TB","PB"];
    let i = 0;
    let n = bytes;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    const dec = (i === 0) ? 0 : (i === 1 ? 1 : 2);
    const nf = new Intl.NumberFormat(LOCALE, { minimumFractionDigits: dec, maximumFractionDigits: dec });
    return `${nf.format(n)} ${units[i]}`;
  }

  function formatDate(ts) {
    if (!ts) return "—";
    try { return new Date(ts * 1000).toLocaleString(LOCALE); } catch { return "—"; }
  }

  function formatDuration(ms) {
    ms = Math.max(0, Number(ms || 0));
    if (ms < 1000) return `${nfInt.format(ms)} ms`;
    const s = ms / 1000;
    if (s < 60) return `${new Intl.NumberFormat(LOCALE, { maximumFractionDigits: 1 }).format(s)} s`;
    const m = Math.floor(s / 60);
    const rem = s - (m * 60);
    return `${nfInt.format(m)} min ${new Intl.NumberFormat(LOCALE, { maximumFractionDigits: 1 }).format(rem)} s`;
  }

  function escapeHtml(s) {
    return String(s || '').replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  }

  function iconHtml(type) {
    return type === 'dir'
      ? `<i class="bi bi-folder-fill text-warning"></i>`
      : `<i class="bi bi-file-earmark text-secondary"></i>`;
  }

  function pct(p) {
    const v = Math.max(0, Math.min(1, Number(p || 0))) * 100;
    return `${nfDec2.format(v)}%`;
  }

  function loadSel() {
    try {
      const raw = localStorage.getItem(LS_SEL);
      const data = raw ? JSON.parse(raw) : [];
      return Array.isArray(data) ? data : [];
    } catch { return []; }
  }

  function saveSel(list) {
    localStorage.setItem(LS_SEL, JSON.stringify(list));
    updateSelBadge();
  }

  function updateSelBadge() {
    selBadge.textContent = String(loadSel().length);
  }

  function clearSel() {
    localStorage.removeItem(LS_SEL);
    updateSelBadge();
    renderSelected();
  }

  function selSet() {
    return new Set(loadSel().map(x => x.rel_path));
  }

  function addToSel(item) {
    const sel = loadSel();
    if (sel.some(x => x.rel_path === item.rel_path)) {
      showToast(t('exists'));
      return;
    }
    sel.push(item);
    saveSel(sel);
    showToast(t('added_ok'));
    renderSelected();
    renderItems();
    renderTopFiles();
    renderTopDirs();
    renderDiag();
  }

  function removeFromSel(rel) {
    const sel = loadSel().filter(x => x.rel_path !== rel);
    saveSel(sel);
    showToast(t('removed'));
    renderSelected();
    renderItems();
    renderTopFiles();
    renderTopDirs();
    renderDiag();
  }

  function exportSel() {
    const sel = loadSel().slice();
    sel.sort((a,b) => (b.size||0)-(a.size||0) || String(a.rel_path).localeCompare(String(b.rel_path)));
    const lines = sel.map(x => `${x.rel_path}\t${formatBytes(x.size||0)}`);
    const blob = new Blob([lines.join("\n") + "\n"], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = "phpDiskTree_selection.txt";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    showToast(t('exported'));
  }

  async function apiGet() {
    const url = `?action=get&p=${encodeURIComponent(CURRENT_REL || '')}`;
    const res = await fetch(url, { cache: 'no-store', credentials: 'same-origin' });
    return await res.json();
  }

  async function apiScan() {
    const url = `?action=scan&p=${encodeURIComponent(CURRENT_REL || '')}`;
    const res = await fetch(url, {
      method: 'POST',
      cache: 'no-store',
      credentials: 'same-origin',
      headers: { 'X-CSRF-Token': CSRF_TOKEN }
    });
    return await res.json();
  }

  function setBusy(on) {
    overlay.classList.toggle('d-none', !on);
    btnScan.disabled = on;
    btnRescan.disabled = on;
  }

  function showLock(lock) {
    lockState = lock || { exists:false, stale:false, age_sec:0 };
    if (lockState.exists && !lockState.stale) {
      const mins = Math.max(1, Math.round((lockState.age_sec||0)/60));
      lockText.textContent = t('scan_lock_msg').replace('{mins}', String(mins));
      lockAlert.classList.remove('d-none');
    } else {
      lockAlert.classList.add('d-none');
    }
  }

  function showStaleWarning(scannedAtTs) {
    if (!scannedAtTs) { staleAlert.classList.add('d-none'); return; }
    const now = Math.floor(Date.now()/1000);
    const age = now - scannedAtTs;
    if (age > CACHE_STALE_SECONDS) {
      const hours = Math.max(12, Math.round(age/3600));
      staleText.textContent = t('stale_cache').replace('{hours}', String(hours));
      staleAlert.classList.remove('d-none');
    } else {
      staleAlert.classList.add('d-none');
    }
  }

  function renderStats() {
    statTotal.textContent = formatBytes(rootStats.root_total_size || 0);
    statFiles.textContent = nfInt.format(rootStats.root_file_count || 0);
    statDirs.textContent  = nfInt.format(rootStats.root_dir_count  || 0);
  }

  function renderScanInfo(exists) {
    if (!exists) {
      scanInfo.innerHTML = `<span class="badge text-bg-secondary me-2">${escapeHtml(t('badge_no_cache'))}</span>${escapeHtml(t('cache_missing'))}`;
      btnScan.classList.remove('d-none');
      btnRescan.classList.add('d-none');
      return;
    }
    const when = scannedAt ? formatDate(scannedAt) : '—';
    const dur = scanDurationMs ? ` (${escapeHtml(formatDuration(scanDurationMs))})` : '';
    scanInfo.innerHTML =
      `<span class="badge text-bg-success me-2">${escapeHtml(t('cache_loaded'))}</span>` +
      `${escapeHtml(t('scan_complete_at'))}: <strong>${escapeHtml(when)}</strong>${dur}`;
    btnScan.classList.add('d-none');
    btnRescan.classList.remove('d-none');
  }

  function filteredItems() {
    const q = (filterInput.value || '').trim().toLowerCase();
    if (!q) return lastItems.slice();
    return lastItems.filter(it => String(it.name||'').toLowerCase().includes(q));
  }

  function renderItems() {
    const items = filteredItems();
    const total = items.length;
    const pages = Math.max(1, Math.ceil(total / pageSize));
    currentPage = Math.min(Math.max(1, currentPage), pages);

    const fromIdx = (currentPage - 1) * pageSize;
    const toIdx = Math.min(total, fromIdx + pageSize);
    const slice = items.slice(fromIdx, toIdx);

    itemsInfo.textContent = t('showing_info')
      .replace('{from}', total ? String(fromIdx + 1) : '0')
      .replace('{to}', String(toIdx))
      .replace('{total}', String(total));

    pageInfo.textContent = t('page_info')
      .replace('{page}', String(currentPage))
      .replace('{pages}', String(pages));

    btnPrev.disabled = (currentPage <= 1);
    btnNext.disabled = (currentPage >= pages);

    if (!slice.length) {
      tbodyItems.innerHTML = `<tr><td colspan="6" class="text-center py-5 text-secondary">${escapeHtml(t('no_items_found'))}</td></tr>`;
      return;
    }

    const sel = selSet();

    tbodyItems.innerHTML = slice.map(it => {
      const isDir = it.type === 'dir';
      const relp = it.rel_path || '';
      const already = sel.has(relp);

      const width = Math.max(0, Math.min(100, (Number(it.percent||0) * 100)));
      const counts = isDir ? `${nfInt.format(it.dir_count||0)} / ${nfInt.format(it.file_count||0)}` : '—';

      const nameHtml = isDir
        ? `<a href="?p=${encodeURIComponent(relp)}" class="link-primary fw-semibold">${escapeHtml(it.name||'')}</a>`
        : `<span class="fw-semibold">${escapeHtml(it.name||'')}</span>`;

      const addBtn = already
        ? `<button class="btn btn-sm btn-outline-success btn-icon" disabled title="${escapeHtml(t('already_selected'))}">
             <i class="bi bi-check-circle-fill"></i>
           </button>`
        : `<button class="btn btn-sm btn-outline-secondary btn-icon js-add"
             data-rel="${escapeHtml(relp)}"
             data-type="${escapeHtml(it.type)}"
             data-name="${escapeHtml(it.name||'')}"
             data-size="${Number(it.size||0)}"
             data-mtime="${Number(it.mtime||0)}"
             title="${escapeHtml(t('added'))}">
             <i class="bi bi-plus-circle"></i>
           </button>`;

      return `
        <tr>
          <td>
            <div class="name-cell">
              <div class="name-bar" style="width:${width.toFixed(2)}%"></div>
              <div class="name-content d-flex align-items-center gap-2">
                ${iconHtml(it.type)}
                <div class="truncate text-truncate" title="${escapeHtml(it.name||'')}">
                  ${nameHtml}
                </div>
              </div>
            </div>
          </td>
          <td class="text-center">${addBtn}</td>
          <td class="text-nowrap">${formatBytes(it.size||0)}</td>
          <td class="text-nowrap">${pct(it.percent||0)}</td>
          <td class="text-nowrap">${formatDate(it.mtime||0)}</td>
          <td class="text-nowrap">${counts}</td>
        </tr>
      `;
    }).join('');
  }

  function renderTopFiles() {
    const list = scopeFilesCur.checked ? topFilesCur : topFilesRoot;
    if (!list || !list.length) {
      tbodyTopFiles.innerHTML =
        `<tr><td colspan="4" class="text-center py-5 text-secondary">${escapeHtml(t('no_top_yet'))}</td></tr>`;
      return;
    }
  
    const sel = selSet();
    tbodyTopFiles.innerHTML = list.map(x => {
      const rel = x.rel_path;
      const already = sel.has(rel);
      const folderRel = x.dir_rel || '';
      const folderLabel = folderRel ? folderRel : t('folder_label_root');
  
      const addBtn = already
        ? `<button class="btn btn-sm btn-outline-success btn-icon" disabled
             title="${escapeHtml(t('already_selected'))}">
             <i class="bi bi-check-circle-fill"></i></button>`
        : `<button class="btn btn-sm btn-outline-secondary btn-icon js-add-top"
             data-rel="${escapeHtml(rel)}"
             data-type="file"
             data-name="${escapeHtml(x.name||'')}"
             data-size="${Number(x.size||0)}"
             data-mtime="${Number(x.mtime||0)}"
             title="${escapeHtml(t('added'))}">
             <i class="bi bi-plus-circle"></i></button>`;
  
      return `
        <tr>
          <td class="text-truncate" style="max-width: 740px;">
            <span class="badge text-bg-light text-secondary border me-2">
              <i class="bi bi-file-earmark"></i>
            </span>
            <span class="fw-semibold">${escapeHtml(x.name||'')}</span>
            <div class="small mono">
              <a class="link-primary" href="?p=${encodeURIComponent(folderRel)}">
                <i class="bi bi-folder2-open me-1"></i>${escapeHtml(folderLabel)}
              </a>
            </div>
          </td>
          <td class="text-center">${addBtn}</td>
          <td class="text-nowrap">${formatBytes(x.size||0)}</td>
          <td class="text-nowrap">${formatDate(x.mtime||0)}</td>
        </tr>
      `;
    }).join('');
  }

  function renderTopDirs() {
    const list = scopeDirsCur.checked ? topDirsCur : topDirsRoot;
    if (!list || !list.length) {
      tbodyTopDirs.innerHTML = `<tr><td colspan="5" class="text-center py-5 text-secondary">${escapeHtml(t('no_top_yet'))}</td></tr>`;
      return;
    }
    const sel = selSet();
    tbodyTopDirs.innerHTML = list.map(x => {
      const rel = x.rel_path;
      const already = sel.has(rel);
      const addBtn = already
        ? `<button class="btn btn-sm btn-outline-success btn-icon" disabled title="${escapeHtml(t('already_selected'))}"><i class="bi bi-check-circle-fill"></i></button>`
        : `<button class="btn btn-sm btn-outline-secondary btn-icon js-add-top"
             data-rel="${escapeHtml(rel)}"
             data-type="dir"
             data-name="${escapeHtml(x.name||'')}"
             data-size="${Number(x.size||0)}"
             data-mtime="${Number(x.mtime||0)}"
             title="${escapeHtml(t('added'))}"><i class="bi bi-plus-circle"></i></button>`;

      const counts = `${nfInt.format(x.dir_count||0)} / ${nfInt.format(x.file_count||0)}`;

      return `
        <tr>
          <td class="text-truncate" style="max-width: 740px;" title="${escapeHtml(rel)}">
            <span class="badge text-bg-light text-secondary border me-2"><i class="bi bi-folder"></i></span>
            <a class="link-primary fw-semibold" href="?p=${encodeURIComponent(rel)}">${escapeHtml(x.name||'')}</a>
            <div class="small text-secondary mono">${escapeHtml(rel)}</div>
          </td>
          <td class="text-center">${addBtn}</td>
          <td class="text-nowrap">${formatBytes(x.size||0)}</td>
          <td class="text-nowrap">${formatDate(x.mtime||0)}</td>
          <td class="text-nowrap">${counts}</td>
        </tr>
      `;
    }).join('');
  }

  function renderSelected() {
    const sel = loadSel().slice();
    sel.sort((a,b) => (b.size||0)-(a.size||0) || String(a.rel_path).localeCompare(String(b.rel_path)));
    updateSelBadge();

    if (!sel.length) {
      tbodySelected.innerHTML = `<tr><td colspan="5" class="text-center py-5 text-secondary">—</td></tr>`;
      selTotals.textContent = '—';
      return;
    }

    const totalSize = sel.reduce((acc,x) => acc + (Number(x.size||0)), 0);
    const label = (sel.length === 1) ? t('sel_item_singular') : t('sel_item_plural');
    selTotals.textContent = `${formatBytes(totalSize)} • ${nfInt.format(sel.length)} ${label}`;

    tbodySelected.innerHTML = sel.map(x => {
      const rel = x.rel_path;
      const type = x.type === 'dir' ? 'dir' : 'file';
      return `
        <tr>
          <td class="text-truncate" style="max-width: 740px;" title="${escapeHtml(rel)}">
            <span class="badge text-bg-light text-secondary border me-2">${type==='dir' ? '<i class="bi bi-folder"></i>' : '<i class="bi bi-file-earmark"></i>'}</span>
            <span class="fw-semibold">${escapeHtml(x.name || rel.split('/').pop() || rel)}</span>
            <div class="small text-secondary mono">${escapeHtml(rel)}</div>
          </td>
          <td class="text-nowrap">${escapeHtml(type==='dir' ? t('type_dir') : t('type_file'))}</td>
          <td class="text-nowrap">${formatBytes(x.size||0)}</td>
          <td class="text-nowrap">${formatDate(x.mtime||0)}</td>
          <td class="text-center">
            <button class="btn btn-sm btn-outline-danger btn-icon js-remove" data-rel="${escapeHtml(rel)}" title="${escapeHtml(t('remove'))}">
              <i class="bi bi-x-circle"></i>
            </button>
          </td>
        </tr>
      `;
    }).join('');
  }

  function renderDiag() {
    const hasCache = !!scannedAt;
    diagCache.textContent = hasCache ? "OK" : "—";
    diagLock.textContent = (lockState && lockState.exists && !lockState.stale) ? "RUNNING" : "—";
    diagLastScan.textContent = hasCache ? formatDate(scannedAt) : "—";
    diagDuration.textContent = hasCache ? formatDuration(scanDurationMs) : "—";

    if (hasCache) {
      const age = Math.floor(Date.now()/1000) - scannedAt;
      const h = Math.floor(age/3600);
      const m = Math.floor((age%3600)/60);
      diagCacheAge.textContent = (h>0) ? `${nfInt.format(h)} h ${nfInt.format(m)} min` : `${nfInt.format(m)} min`;
    } else {
      diagCacheAge.textContent = "—";
    }

    diagCurrent.textContent = CURRENT_REL ? CURRENT_REL : t('folder_label_root');
    diagRootTotal.textContent = hasCache ? formatBytes(rootStats.root_total_size||0) : "—";

    const sel = loadSel();
    const selSize = sel.reduce((acc,x)=>acc+(Number(x.size||0)),0);
    diagSel.textContent = `${nfInt.format(sel.length)} • ${formatBytes(selSize)}`;

    diagPhp.textContent = phpVersion || "—";
    diagMemLimit.textContent = (memLimitBytes != null && memLimitBytes >= 0) ? formatBytes(memLimitBytes) : "∞";
    diagPeak.textContent = peakMemBytes ? formatBytes(peakMemBytes) : "—";
  }

  async function loadAll() {
    try {
      const r = await apiGet();
      if (!r.ok) throw new Error(r.error || "Load failed");

      showLock(r.lock || { exists:false, stale:false, age_sec:0 });

      // force clear selection if initial scan is pending (or scan running without cache)
      if (r.initial_scan_pending || (!r.exists && r.scan_in_progress)) {
        clearSel();
      }

      if (!r.exists) {
        scannedAt = 0;
        scanDurationMs = 0;
        peakMemBytes = 0;
        memLimitBytes = (r.server && r.server.memory_limit_bytes != null) ? r.server.memory_limit_bytes : -1;
        phpVersion = (r.server && r.server.php_version) ? r.server.php_version : '';
        rootStats = { root_total_size:0, root_file_count:0, root_dir_count:0 };
        lastItems = [];
        topFilesRoot = topFilesCur = [];
        topDirsRoot = topDirsCur = [];

        renderStats();
        renderScanInfo(false);
        staleAlert.classList.add('d-none');

        tbodyItems.innerHTML = `<tr><td colspan="6" class="text-center py-5 text-secondary">${escapeHtml(t('no_data_yet'))}</td></tr>`;
        itemsInfo.textContent = '—';
        pageInfo.textContent = '—';
        tbodyTopFiles.innerHTML = `<tr><td colspan="5" class="text-center py-5 text-secondary">${escapeHtml(t('no_top_yet'))}</td></tr>`;
        tbodyTopDirs.innerHTML = `<tr><td colspan="5" class="text-center py-5 text-secondary">${escapeHtml(t('no_top_yet'))}</td></tr>`;

        renderSelected();
        renderDiag();
        return;
      }

      scannedAt = r.scanned_at || 0;
      scanDurationMs = r.scan_duration_ms || 0;
      peakMemBytes = r.scan_peak_memory_bytes || 0;
      memLimitBytes = (r.scan_memory_limit_bytes != null) ? r.scan_memory_limit_bytes : -1;
      phpVersion = r.php_version || '';
      rootStats = r.stats || rootStats;

      renderStats();
      renderScanInfo(true);
      showStaleWarning(scannedAt);

      lastItems = (r.current && r.current.items) ? r.current.items : [];
      topFilesRoot = r.top_files_global || [];
      topFilesCur  = r.top_files_current || [];
      topDirsRoot  = r.top_dirs_global || [];
      topDirsCur   = r.top_dirs_current || [];

      currentPage = 1;
      renderItems();
      renderTopFiles();
      renderTopDirs();
      renderSelected();
      renderDiag();
    } catch (e) {
      showToast(e.message || "Erro ao carregar.");
    }
  }

  async function runScan() {
    setBusy(true);
    try {
      const r = await apiScan();
      if (!r.ok) throw new Error(r.error || "Scan error");
      await loadAll();
    } catch (e) {
      showToast(e.message || "Scan error");
      await loadAll(); // refresh lock/cache state
    } finally {
      setBusy(false);
    }
  }

  btnScan.addEventListener('click', runScan);
  btnRescan.addEventListener('click', runScan);

  filterInput.addEventListener('input', () => { currentPage = 1; renderItems(); });
  btnClearFilter.addEventListener('click', () => { filterInput.value=''; currentPage=1; renderItems(); filterInput.focus(); });

  pageSizeSelect.addEventListener('change', () => {
    pageSize = parseInt(pageSizeSelect.value || "150", 10);
    currentPage = 1;
    renderItems();
  });

  btnPrev.addEventListener('click', () => { currentPage = Math.max(1, currentPage-1); renderItems(); });
  btnNext.addEventListener('click', () => { currentPage = currentPage+1; renderItems(); });

  scopeFilesRoot.addEventListener('change', renderTopFiles);
  scopeFilesCur.addEventListener('change', renderTopFiles);
  scopeDirsRoot.addEventListener('change', renderTopDirs);
  scopeDirsCur.addEventListener('change', renderTopDirs);

  tbodyItems.addEventListener('click', (ev) => {
    const btn = ev.target.closest('.js-add');
    if (!btn) return;
    addToSel({
      rel_path: btn.dataset.rel,
      type: btn.dataset.type,
      name: btn.dataset.name,
      size: Number(btn.dataset.size || 0),
      mtime: Number(btn.dataset.mtime || 0)
    });
  });

  function onTopAdd(ev) {
    const btn = ev.target.closest('.js-add-top');
    if (!btn) return;
    addToSel({
      rel_path: btn.dataset.rel,
      type: btn.dataset.type,
      name: btn.dataset.name,
      size: Number(btn.dataset.size || 0),
      mtime: Number(btn.dataset.mtime || 0)
    });
  }
  tbodyTopFiles.addEventListener('click', onTopAdd);
  tbodyTopDirs.addEventListener('click', onTopAdd);

  tbodySelected.addEventListener('click', (ev) => {
    const btn = ev.target.closest('.js-remove');
    if (!btn) return;
    removeFromSel(btn.dataset.rel);
  });

  btnClearSel.addEventListener('click', () => {
    if (confirm(t('confirm_clear'))) clearSel();
    renderDiag();
  });

  btnExport.addEventListener('click', exportSel);

  langSelect.addEventListener('change', () => {
    const newLang = (langSelect.value === 'en') ? 'en' : 'pt';
    localStorage.setItem(LS_LANG, newLang);
    setLocale(newLang);
    applyI18n();
    renderScanInfo(!!scannedAt);
    showStaleWarning(scannedAt);
    renderStats();
    renderItems();
    renderTopFiles();
    renderTopDirs();
    renderSelected();
    renderDiag();
  });

  setLocale(detectLang());
  langSelect.value = lang;
  applyI18n();
  updateSelBadge();
  renderSelected();
  loadAll();
  setInterval(() => { if (scannedAt) renderDiag(); }, 60000);
</script>
</body>
</html>
