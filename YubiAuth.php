<?php
/**
 * Class for verifying Yubico OTP
 * 
 * Created by Matyáš Koc
 *
 * Published under Creative Commons BY-NC-SA license
 */
class YubiAuth {
    
	private $api_id;
	private $api_key;
	private $server;
	
	/* Creates a new validation object - requires ID and API key, accepts custom server */
    public function __construct($api_id, $api_key, $server = 'https://api.yubico.com/wsapi/2.0/verify') {
        
		$this->api_id = $api_id;
		$this->api_key = $api_key;
		$this->server = $server;
		
    }
	
	/* Validates OTP using validation server, then tests if the OTP matches to user key ID */
	public function validate($otp, $key_id) {
		
		/* Prepare query and make hash for validation */
		$urlparams = "id=". $this->api_id ."&nonce=". $this->cryptoRandomNonce() ."&otp=". $otp;
		$h = urlencode($this->makeSignature($urlparams));
		
		/* Do the query */
		$response = $this->queryServer($this->server ."?". $urlparams ."&h=". $h);
		
		/* Make array from result */
		$response = $this->parseResultToArray($response);
		
		/* Validate response signature */
		if (!$this->validateHash($response)) {
			return false;
		}
		
		/* Validate status */
		if (!$this->validateStatus($response)) {
			return false;
		}
		
		/* Check if key ID matches supplied correct one */
		if (!$this->validateKeyID($otp, $key_id)) {
			return false;
		}
		
		return true;
		
	}
	
	/* Make query to validation server using cURL */
	private function queryServer($url) {
		
		$options = array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HEADER         => false,
			CURLOPT_ENCODING       => "",
			CURLOPT_SSL_VERIFYHOST => 2,
			CURLOPT_SSL_VERIFYPEER => true,
		); 
		
		$ch = curl_init($url);
		curl_setopt_array($ch, $options);
		$content = curl_exec($ch);
		curl_close($ch);
		
		return $content;
		
	}
	
	/* Generate HMAC hash for validation */
	private function makeSignature($data) {
		
		$signature = base64_encode(hash_hmac("sha1", $data, base64_decode($this->api_key), true));
		return $signature;
		
	}
	
	/* Generate cryptographically strong random alphanumeric nonce */
	private function cryptoRandomNonce() {
		
		return preg_replace("/[^A-Za-z0-9 ]/", '', base64_encode(openssl_random_pseudo_bytes(14)));
		
	}
	
	/* Make sorted array from result */
	private function parseResultToArray($result) {
		
		$result_array = explode("\n", $result);
		
		/* This removes all nonprintable and NULL fields from array */
		foreach ($result_array as $key => $param) {
			
			$param = preg_replace('/[\x00-\x1F\x7F]/u', '', $param);
			
			if ($param == NULL) {
				unset($result_array[$key]);
			}
			
		}
		
		asort($result_array);
		
		return $result_array;
		
	}
	
	/* Validates response from array */
	private function validateHash($result_array) {
		
		/* Look for the response signature and put it aside + make string from params */
		foreach ($result_array as $key => $param) {
			
			if (substr($param, 0, 1) == "h") {
				$signature = $param;
				unset($result_array[$key]);
				continue;
			}
			
			$result_string .= $param . "&";
			
		}
		
		/* Remove whitespace and last & from string */
		$result_string = preg_replace('/\s/', '', $result_string);
		$result_string = substr($result_string, 0, -1);
		
		/* Remove the h= and whitespace from signature */
		$signature = substr($signature, 2);
		$signature = preg_replace('/\s/', '', $signature);
		
		/* Hash it and then compare */
		if ($this->makeSignature($result_string) == $signature) {
			return true;
		}
		
		return false;
		
	}
	
	/* Validates status from array */
	private function validateStatus($result_array) {
		
		/* Look for the status */
		foreach ($result_array as $param) {
			
			if (substr($param, 0, 6) == "status") {
				$status = $param;
				break;
			}
			
		}

		/* Remove whirespace from status */
		$status = preg_replace('/\s/', '', $status);
		
		/* Check if status is OK, ignore case */
		if (strtolower($status) == "status=ok") {
			return true;
		}
		
		return false;
		
	}
	
	/* Validates if key ID matches the supplied correct one */
	private function validateKeyID($otp, $key_id) {
		
		/* Key ID are the first 12 characters in OTP */
		$otp_key_id = substr($otp, 0, 12);

		/* Check if key ID is correct */
		if ($otp_key_id == $key_id) {
			return true;
		}
		
		return false;
		
	}
    
}
?>