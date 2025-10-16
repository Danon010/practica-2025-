verification_email_html = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #f4f4f4; padding: 10px; text-align: center; }
        .button { display: inline-block; padding: 12px 24px; background: #007bff; 
                 color: white; text-decoration: none; border-radius: 4px; }
        .footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd; 
                 font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Vulnerability Scanner</h1>
        </div>
        <h2>Verify Your Email Address</h2>
        <p>Thank you for registering with our Vulnerability Scanner service.</p>
        <p>Please click the button below to verify your email address:</p>
        <p>
            <a href="{verification_url}" class="button">Verify Email Address</a>
        </p>
        <p>If the button doesn't work, copy and paste this link into your browser:</p>
        <p>{verification_url}</p>
        <div class="footer">
            <p>If you didn't create this account, please ignore this email.</p>
        </div>
    </div>
</body>
</html>
"""

password_reset_email_html = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #f4f4f4; padding: 10px; text-align: center; }
        .button { display: inline-block; padding: 12px 24px; background: #dc3545; 
                 color: white; text-decoration: none; border-radius: 4px; }
        .footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd; 
                 font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Vulnerability Scanner</h1>
        </div>
        <h2>Password Reset Request</h2>
        <p>We received a request to reset your password for your Vulnerability Scanner account.</p>
        <p>Click the button below to reset your password:</p>
        <p>
            <a href="{reset_url}" class="button">Reset Password</a>
        </p>
        <p>If the button doesn't work, copy and paste this link into your browser:</p>
        <p>{reset_url}</p>
        <p><strong>This link will expire in 1 hour.</strong></p>
        <div class="footer">
            <p>If you didn't request a password reset, please ignore this email.</p>
        </div>
    </div>
</body>
</html>
"""

scan_completed_email_html = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #f4f4f4; padding: 10px; text-align: center; }
        .success { color: #28a745; }
        .warning { color: #ffc107; }
        .danger { color: #dc3545; }
        .footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd; 
                 font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Vulnerability Scanner</h1>
        </div>
        <h2>Scan Completed</h2>
        <p>Your security scan for <strong>{target}</strong> has been completed.</p>
        <p><strong>Scan Results:</strong></p>
        <ul>
            <li>Total vulnerabilities found: <strong>{total_vulnerabilities}</strong></li>
            <li>Critical: <span class="danger">{critical_count}</span></li>
            <li>High: <span class="warning">{high_count}</span></li>
            <li>Medium: <span class="warning">{medium_count}</span></li>
            <li>Low: <span>{low_count}</span></li>
        </ul>
        <p>You can view the detailed report in your Vulnerability Scanner dashboard.</p>
        <div class="footer">
            <p>This is an automated message. Please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
"""
