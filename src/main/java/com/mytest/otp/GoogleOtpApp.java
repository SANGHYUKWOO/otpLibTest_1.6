package com.mytest.otp;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;

import java.util.Map;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base32;
//import org.apache.commons.configuration.Configuration;
/*import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.bind.annotation.RequestMapping;*/

/**
 * Handles requests for the application home page.
 */
public class GoogleOtpApp {
	
	//private static final Logger logger = LoggerFactory.getLogger(GoogleOtpApp.class);

	/**
	 * 비밀키 생성하여 사용
	 * @param model
	 * @param id
	 * @param pw
	 * @param user
	 * @param host
	 * @return
	 */
	public Map<String, String> googleOTPAuth( String id, String pw, String user, String host) {
			//String secretKeyStr = "GXRZIYSI";// 매번 생성하지 않고 한번 생성된 키를 사용.
			//String secretKeyStr   = "WSHRFVTG";// 매번 생성하지 않고 한번 생성된 키를 사용.
			String secretKeyStr = generateSecretKey();// 매번 생성
			//String url = getQRBarcodeURL("kw191211", "testEmail.com", secretKeyStr); // 생성된 바코드 주소!
			String url = getQRBarcodeURL(user, host, secretKeyStr); // 생성된 바코드 주소!
	        System.out.println("URL : " + url);
	        
			//model.addAttribute("secretKey", secretKeyStr);
			//model.addAttribute("url", url);
	        
	        HashMap<String, String> map = new HashMap<String, String>();
	        
	        map.put("secretKey", secretKeyStr);
	        map.put("url", url);
			//otp 생성
			return map;
	}
	
	/**
	 * 비밀키 생성하여 사용
	 * @param model
	 * @param id
	 * @param pw
	 * @param user
	 * @param host
	 * @return
	 */
	public Map<String, String> googleOTPAuth( String user, String host) {
			//String secretKeyStr = "GXRZIYSI";// 매번 생성하지 않고 한번 생성된 키를 사용.
			//String secretKeyStr   = "WSHRFVTG";// 매번 생성하지 않고 한번 생성된 키를 사용.
			String secretKeyStr = generateSecretKey();// 매번 생성
			//String url = getQRBarcodeURL("kw191211", "testEmail.com", secretKeyStr); // 생성된 바코드 주소!
			String url = getQRBarcodeURL(user, host, secretKeyStr); // 생성된 바코드 주소!
	        System.out.println("URL : " + url);
	        
			//model.addAttribute("secretKey", secretKeyStr);
			//model.addAttribute("url", url);
	        
	        HashMap<String, String> map = new HashMap<String, String>();
	        
	        map.put("secretKey", secretKeyStr);
	        map.put("url", url);
			//otp 생성
			return map;
	}
	
	/**
	 * 공용 비밀키 사용
	 * @param model
	 * @param id
	 * @param pw
	 * @param user
	 * @param host
	 * @param secretKeyStr
	 * @return
	 */
	public Map<String, String> googleOTPAuth(String id, String pw, String user, String host, String secretKeyStr) {
		//String secretKeyStr = "GXRZIYSI";// 매번 생성하지 않고 한번 생성된 키를 사용.
		//String secretKeyStr   = "WSHRFVTG";// 매번 생성하지 않고 한번 생성된 키를 사용.
		//String secretKeyStr = generateSecretKey();// 매번 생성
		//String url = getQRBarcodeURL("kw191211", "testEmail.com", secretKeyStr); // 생성된 바코드 주소!
		String url = getQRBarcodeURL(user, host, secretKeyStr); // 생성된 바코드 주소!
        System.out.println("URL : " + url);
        
		//model.addAttribute("secretKey", secretKeyStr);
		//model.addAttribute("url", url);
        
        HashMap<String, String> map = new HashMap<String, String>();
        
        map.put("secretKey", secretKeyStr);
        map.put("url", url);
		//otp 생성
		return map;
	}
	
	/**
	 * 공용 비밀키 사용
	 * @param model
	 * @param id
	 * @param pw
	 * @param user
	 * @param host
	 * @param secretKeyStr
	 * @return
	 */
	public Map<String, String> googleOTPAuth( String user, String host, String secretKeyStr) {
		//String secretKeyStr = "GXRZIYSI";// 매번 생성하지 않고 한번 생성된 키를 사용.
		//String secretKeyStr   = "WSHRFVTG";// 매번 생성하지 않고 한번 생성된 키를 사용.
		//String secretKeyStr = generateSecretKey();// 매번 생성
		//String url = getQRBarcodeURL("kw191211", "testEmail.com", secretKeyStr); // 생성된 바코드 주소!
		String url = getQRBarcodeURL(user, host, secretKeyStr); // 생성된 바코드 주소!
        System.out.println("URL : " + url);
        
		//model.addAttribute("secretKey", secretKeyStr);
		//model.addAttribute("url", url);
        
        HashMap<String, String> map = new HashMap<String, String>();
        
        map.put("secretKey", secretKeyStr);
        map.put("url", url);
		//otp 생성
		return map;
	}

	/**
	 * 
	 * @param req
	 * @return
	 */
	public boolean select(HttpServletRequest req) {
		//사용자가 입력한 OTP 6자리 숫자
		String user_codeStr = req.getParameter("user_code");
        long user_code = Integer.parseInt(user_codeStr);
        //secretKeyStr 로 세팅한 비밀키
        String encodedKey = req.getParameter("secretKey");
        long l = new Date().getTime();
        long ll =  l / 30000;
         
        boolean check_code = false;
        try {
            // 키, 코드, 시간으로 일회용 비밀번호가 맞는지 일치 여부 확인.
        	//비밀키, OTP 코드 , 현재 시간
            check_code = check_code(encodedKey, user_code, ll);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        
        return check_code;
	}
	
	/**
	 * 
	 * @return
	 */
	private String generateSecretKey(){		
		// Allocating the buffer
        //byte[] buffer = new byte[secretSize + numOfScratchCodes * scratchCodeSize];
        byte[] buffer = new byte[5 + 5 * 5];
         
        // Filling the buffer with random numbers.
        // Notice: you want to reuse the same random generator
        // while generating larger random number sequences.
        new Random().nextBytes(buffer);
 
        Base32 codec = new Base32();
        byte[] secretKey = Arrays.copyOf(buffer, 5);
        byte[] bEncodedKey = codec.encode(secretKey);
         
        // 생성된 Key!
        String encodedKey = new String(bEncodedKey);
         
        System.out.println("encodedKey : " + encodedKey);
        
        
        return encodedKey;
	}
	
	/**
	 * 
	 * @param user
	 * @param host
	 * @param secret
	 * @return
	 */
	private static String getQRBarcodeURL(String user, String host, String secret) {
        //String format = "http://chart.apis.google.com/chart?cht=qr&amp;chs=300x300&amp;chl=otpauth://totp/%s@%s%%3Fsecret%%3D%s&amp;chld=H|0";
		String format = "https://chart.googleapis.com/chart?cht=qr&amp;chs=300x300&amp;chl=otpauth://totp/%s@%s%%3Fsecret%%3D%s&amp;chld=H|0";
		//%3D = =
		//%3F = ?
		//스트링 포멧  http://chart.googleapis.com/chart?cht=qr&amp;chs=300x300&amp;chl=otpauth://totp/kw191211@testEmail.com%3Fsecret%3DWSHRFVTG&amp;chld=H|0
		//스트링 포멧  http://chart.googleapis.com/chart?cht=qr&chs=300x300&chl=otpauth://totp/kw191211@testEmail.com?secret=WSHRFVTG&chld=H|0
        System.out.println(" 스트링 포멧  "+String.format(format, user, host, secret));
        return String.format(format, user, host, secret);
    }
	
	//키, 코드, 시간으로 일회용 비밀번호가 맞는지 일치 여부 확인.
	//비밀키, OTP 코드 , 현재 시간
	/**
	 * 
	 * @param secret
	 * @param code
	 * @param t
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	private static boolean check_code(String secret, long code, long t) throws NoSuchAlgorithmException, InvalidKeyException {
        Base32 codec = new Base32();
        byte[] decodedKey = codec.decode(secret);
 
        int window = 3;
        for (int i = -window; i <= window; ++i) {
            long hash = verifyGoogleOtp(decodedKey, t + i);
 
            if (hash == code) {
                return true;
            }
        }
 
        return false;
    }
	
	
	//OTP와 secret Key간의 검증
	/**
	 * 
	 * @param key
	 * @param t
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	private static int verifyGoogleOtp(byte[] key, long t) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] data = new byte[8];
        long value = t;
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }
 
        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signKey);
        byte[] hash = mac.doFinal(data);
 
        int offset = hash[20 - 1] & 0xF;
 
        long truncatedHash = 0;
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            truncatedHash |= (hash[offset + i] & 0xFF);
        }
 
        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= 1000000;
 
        return (int) truncatedHash;
    }
}
