<?php
// === CONFIGURATION ===
$config = require(__DIR__ . '/.env.php');
header('Content-Type: application/json');

$requiredKeys = ['TENANT_ID', 'CLIENT_ID', 'THUMBPRINT', 'FROM_EMAIL', 'HCAPTCHA_SECRET', 'PRIVATE_KEY_PATH'];
foreach ($requiredKeys as $key) {
    if (empty($config[$key])) {
        http_response_code(500);
        echo json_encode([
            "success" => false,
            "error" => "Configuration error: missing $key"
        ]);
        exit;
    }
}

$tenantId       = $config['TENANT_ID'];
$clientId       = $config['CLIENT_ID'];
$privateKey     = file_get_contents($config['PRIVATE_KEY_PATH']);
$thumbprint     = $config['THUMBPRINT'];
$fromEmail      = $config['FROM_EMAIL'];
$hcaptchaSecret = $config['HCAPTCHA_SECRET'];

// === DEPARTMENT EMAIL LOOKUP TABLE ===
$departmentMap = [
    'Board of Directors' => 'board@howloween.ca',
    'Chair' => 'chair@howloween.ca',
    'Charity' => 'charity@howloween.ca',
    'Dances' => 'dances@howloween.ca',
    'Dealers Den' => 'dealersden@howloween.ca',
    'Events' => 'events@howloween.ca',
    'Hotel' => 'hotel@howloween.ca',
    'Information' => 'info@howloween.ca',
    'Photography' => 'photography@howloween.ca',
    'Rangers' => 'rangers@howloween.ca',
    'Registration' => 'registration@howloween.ca',
    'Social Media' => 'socialmedia@howloween.ca',
    'Theater' => 'theater@howloween.ca',
    'Website' => 'website@howloween.ca',
];

// === HCAPTCHA VALIDATION ===

$hcaptchaResponse = $_POST['h-captcha-response'] ?? null;

if (!$hcaptchaResponse) {
    http_response_code(403);
    echo json_encode([
        "success" => false,
        "error" => "Captcha response is required."
    ]);
    exit;
}

$verifyData = [
    'secret'   => $hcaptchaSecret,
    'response' => $hcaptchaResponse,
    'remoteip' => $_SERVER['REMOTE_ADDR']
];

$verify = curl_init();
curl_setopt($verify, CURLOPT_URL, "https://hcaptcha.com/siteverify");
curl_setopt($verify, CURLOPT_POST, true);
curl_setopt($verify, CURLOPT_POSTFIELDS, http_build_query($verifyData));
curl_setopt($verify, CURLOPT_RETURNTRANSFER, true);

$response = curl_exec($verify);
curl_close($verify);

$success = json_decode($response, true)['success'] ?? false;

if (!$success) {
    http_response_code(403);
    echo json_encode([
        "success" => false,
        "error" => "Captcha validation failed."
    ]);
    exit;
}

// === VALIDATE INPUT ===
$department = $_POST['department'] ?? null;
$name       = $_POST['name'] ?? null;
$email      = $_POST['email'] ?? null;
$message    = $_POST['message'] ?? null;

if (!$department || !$name || !$email || !$message) {
    http_response_code(400);
    echo json_encode([
        "success" => false,
        "error" => "Missing one or more required fields: department, name, email, message."
    ]);
    exit;
}

if (!isset($departmentMap[$department])) {
    http_response_code(400);
    echo json_encode([
        "success" => false,
        "error" => "Can't find a department with that name."
    ]);
    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode([
        "success" => false,
        "error" => "Your email doesn't appear to be valid."
    ]);
}

$sanitizedName = htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$sanitizedMessage = htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$toEmail  = $departmentMap[$department];
$subject  = "[CONTACT FORM] New message from $sanitizedName";
$bodyText = "From: $sanitizedName <$email>\nDepartment: $department\n\n$sanitizedMessage";

// === BUILD JWT CLAIM ===
$now = time();
$jwtHeader = base64url_encode(json_encode([
    'alg' => 'RS256',
    'typ' => 'JWT',
    'x5t' => $thumbprint
]));
$jwtPayload = base64url_encode(json_encode([
    'aud' => "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token",
    'iss' => $clientId,
    'sub' => $clientId,
    'jti' => bin2hex(random_bytes(16)),
    'nbf' => $now,
    'exp' => $now + 3600
]));

$jwtToSign = "$jwtHeader.$jwtPayload";
openssl_sign($jwtToSign, $signature, $privateKey, OPENSSL_ALGO_SHA256);
$clientAssertion = "$jwtToSign." . base64url_encode($signature);

// === GET ACCESS TOKEN ===
$tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token";
$tokenData = http_build_query([
    'client_id'             => $clientId,
    'scope'                 => 'https://graph.microsoft.com/.default',
    'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    'client_assertion'      => $clientAssertion,
    'grant_type'            => 'client_credentials'
]);

$ch = curl_init($tokenUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $tokenData);
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
$tokenResponse = curl_exec($ch);
curl_close($ch);

$token = json_decode($tokenResponse, true)['access_token'] ?? null;
if (!$token) {
    http_response_code(500);
    echo json_encode([
        "success" => false,
        "error" => "Failed to obtain access token.",
        "details" => $tokenResponse
    ]);
    exit;
}

// === PREPARE MAIN SEND EMAIL ===
$sendUrl = "https://graph.microsoft.com/v1.0/users/$fromEmail/sendMail";
$emailPayload = [
    'message' => [
        'subject' => $subject,
        'body' => [
            'contentType' => 'Text',
            'content' => $bodyText
        ],
        'toRecipients' => [
            ['emailAddress' => ['address' => $toEmail]]
        ],
        'replyTo' => [
            ['emailAddress' => ['address' => $email]]
        ]
    ],
    'saveToSentItems' => true
];

// === SEND CONFIRMATION TO SENDER ===
$confirmSubject = "We've received your message to Howloween";
$confirmBody = <<<TEXT
Hi $sanitizedName,

Thanks for reaching out to Howloween!
We’ve received your message and someone will get back to you as soon as possible.

If you didn’t submit this message, you can ignore this email.

— The Howloween Team
TEXT;

$confirmPayload = [
    'message' => [
        'subject' => $confirmSubject,
        'body' => [
            'contentType' => 'Text',
            'content' => $confirmBody
        ],
        'toRecipients' => [
            ['emailAddress' => [
                'address' => $email,
                'name' => $sanitizedName
            ]]
        ]
    ],
    'saveToSentItems' => false // optional, to avoid cluttering the shared inbox
];

$ch = curl_init($sendUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($confirmPayload));
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "Authorization: Bearer $token",
    "Content-Type: application/json"
]);
$confirmResponse = curl_exec($ch);
curl_close($ch);

// === PREPARE MAIN SEND EMAIL ===
$ch = curl_init($sendUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($emailPayload));
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "Authorization: Bearer $token",
    "Content-Type: application/json"
]);
$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($httpCode === 202) {
    echo json_encode([
        "success" => true,
        "message" => "Email sent successfully."
    ]);
} else {
    http_response_code($httpCode);
    echo json_encode([
        "success" => false,
        "error" => "Failed to send email.",
        "response" => $response
    ]);
}

// === HELPERS ===
function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}
?>
