# YubiAuth
Easy and portable PHP class for authenticating with YubiKeys

Created by: [Matyáš Koc (Vilican)](https://github.com/Vilican)

Licensed under: [CC-BY-NC-SA](https://creativecommons.org/licenses/by-nc-sa/4.0/) (if you need to use this in your commercial project, contact me)

## How to use

1. Include or require the file to your PHP project

   `require "YubiAuth.php";`

2. Create a new object from this class

   `$yubi = new YubiAuth($api_id, $api_key, $server);`
   
   You can get API ID and API key at https://upgrade.yubico.com/getapikey/
   
   The `$server` variable is not required. If you don't supply it, Yubico server will be used.

3. When validating OTP, use the validate method

   `$result = $yubi->validate($otp, $user_key_id);`
   
   The `$user_key_id` is the ID of user's key, which you probably have in database.

4. Check the result

   `if ($result === TRUE) {  }`
   
   True is returned if everything is OK. False is returned when there is an error.
