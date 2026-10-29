<?php
if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    exit('upload failed');
}

$type = $_FILES['file']['type'];
if (!str_starts_with($type, 'image/')) {
    http_response_code(415);
    exit('images only');
}

$folder = $_POST['folder'] ?? 'incoming';
$name = $_FILES['file']['name'];
$destination = __DIR__ . '/public/uploads/' . $folder . '/' . $name;

$bytes = file_get_contents($_FILES['file']['tmp_name']);
if ($bytes === false || strlen($bytes) === 0) {
    http_response_code(400);
    exit('empty');
}

if (!move_uploaded_file($_FILES['file']['tmp_name'], $destination)) {
    http_response_code(500);
    exit('move failed');
}

echo 'ok';
