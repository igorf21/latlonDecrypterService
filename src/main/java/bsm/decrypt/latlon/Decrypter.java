package bsm.decrypt.latlon;

// Main parsing is in PROCEDURE [dbo].[usp_i_MessageDecoder]
// Raw data is in dbo.MESSAGE_DECODER_QUEUE
// Decrypting is in EXEC dbo.usp_s_DecryptPacket @rawPacket, @outPacket = @decryptedPacket OUTPUT;
// Decoding is in dbo.usp_i_MessageDecoder @rawPacketId

import java.io.BufferedOutputStream;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.camel.Exchange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Timestamp;


public class Decrypter {
	
	
	// Various mapping objects for data decoding
	private Map<String,String> decoderMap = new HashMap<String, String>();

	// Helper members

	
	private static final Logger LOG = LoggerFactory.getLogger(Decrypter.class);

	@SuppressWarnings("unchecked")
	public void decryptMsg(Exchange exchange) throws Exception {
	
		// Initialize Decoder Map
		initDecoderMap();	// This needs to be moved to some sort of cashed object initialized on the start of this interface the 
		// Initialize Decoder Map
		
		Map<String, Object> record = exchange.getIn().getBody(Map.class);

		//SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");

		// RECEIVE_DTTM=2014-08-16 00:06:44.173
		java.sql.Timestamp receiveDttm = (Timestamp) record.get("RECEIVE_DTTM");
		String encryptedMsg = (String)record.get("RAW_PACKET");

		String decryptedMsg = decrypt(encryptedMsg);
		record.put("DECRYPTED_PACKET", decryptedMsg);
		record.remove("RAW_PACKET");
		record.put("RECEIVE_DTTM", receiveDttm.toString());
		
		return;
	}

	private String decrypt(String encodedMsg) {
		
		String packet = encodedMsg.substring(10, encodedMsg.length() - 4);
		
		short iNybbleKey = 4;
		short maxDigit = 16;
		int packetLength = packet.length();
		
		String sShift = encodedMsg.substring(iNybbleKey, iNybbleKey + 1);
		int iShift = hexStringToInt('0' + sShift);
		
		String outPacket = "";
		
		for (int i = 0; i < packetLength; i++){
			
			String fromValue = packet.substring(0,1);
			String sToValue = mapValues(fromValue) ;
			
			int iToValue = hexStringToInt('0' + sToValue);
			iToValue = iToValue - iShift + maxDigit;
			iToValue = iToValue % maxDigit;
			sToValue = Integer.toString(iToValue);

					if (sToValue.equals("10"))
						sToValue = "A";
					else if (sToValue.equals("11"))
						sToValue = "B";
					else if (sToValue.equals("12"))
						sToValue = "C";
					else if (sToValue.equals("13"))
						sToValue = "D";
					else if (sToValue.equals("14"))
						sToValue = "E";
					else if (sToValue.equals("15"))
						sToValue = "F";			

			outPacket = outPacket + sToValue;
			packet = packet.substring(1,packet.length());
		}
		
		return outPacket;
		
	}
	
private int hexStringToInt(String input) {
		
		String bStr = "";
		byte[] result = new byte[4];
		int len = input.length() / 2;

		for (int i = 0; i < len; i++){
			String tmp1 = input.substring( i * 2, i * 2 + 1).toLowerCase();
			int tmpRes1 = 0x00;
			int tmpRes2 = 0x00;
			String tmp2 = input.substring( i * 2 + 1, i * 2 + 2).toLowerCase();
		
			switch (tmp1) {
        	case "0":  tmpRes1 = Integer.decode("0x00");
                 break;
        	case "1":  tmpRes1 = Integer.decode("0x10;");
                 break;
        	case "2":  tmpRes1 = Integer.decode("0x20");
                 break;
        	case "3":  tmpRes1 = Integer.decode("0x30");
                 break;
        	case "4":  tmpRes1 = Integer.decode("0x40");
                 break;
        	case "5":  tmpRes1 = Integer.decode("0x50");
                 break;
        	case "6":  tmpRes1 = Integer.decode("0x60");
                 break;
        	case "7":  tmpRes1 = Integer.decode("0x70");
                 break;
        	case "8":  tmpRes1 = Integer.decode("0x80");
                 break;
        	case "9": tmpRes1 = Integer.decode("0x90");
        		 break;
        	case "a": tmpRes1 = Integer.decode("0xa0"); 
                 break;
        	case "b": tmpRes1 = Integer.decode("0xb0"); 
                 break;
        	case "c": tmpRes1 = Integer.decode("0xc0"); 
        		 break;
        	case "d": tmpRes1 = Integer.decode("0xd0"); 
        		 break;
        	case "e": tmpRes1 = Integer.decode("0xe0"); 
        		 break;
        	case "f": tmpRes1 = Integer.decode("0xf0"); 
                  break;
			}
		
			switch (tmp2) {
        	case "0": tmpRes2 = Integer.decode("0x00");
                 break;
        	case "1": tmpRes2 = Integer.decode("0x01");
                 break;
        	case "2": tmpRes2 = Integer.decode("0x02");
                 break;
        	case "3": tmpRes2 = Integer.decode("0x03");
                 break;
        	case "4": tmpRes2 = Integer.decode("0x04");
                 break;
        	case "5": tmpRes2 = Integer.decode("0x05");
                 break;
        	case "6": tmpRes2 = Integer.decode("0x06");
                 break;
        	case "7": tmpRes2 = Integer.decode("0x07");
                 break;
        	case "8": tmpRes2 = Integer.decode("0x08");
                 break;
        	case "9": tmpRes1 = Integer.decode("0x09");
                 break;
        	case "a": tmpRes2 = Integer.decode("0x0a");
                 break;
        	case "b": tmpRes2 = Integer.decode("0x0b");
                 break;
        	case "c": tmpRes2 = Integer.decode("0x0c");
        		 break;
        	case "d": tmpRes2 = Integer.decode("0x0d");
        		 break;
        	case "e": tmpRes2 = Integer.decode("0x0e");
        		 break;
        	case "f": tmpRes2 = Integer.decode("0x0f");
                 break;
			}
			
			bStr = bStr + Integer.toBinaryString(tmpRes1 | tmpRes2);
		}

		return Integer.parseInt(bStr, 2);
	}
	
	private String mapValues(String fromValue) {
	
		String toValue = decoderMap.get(fromValue);
		return toValue;
	}
	
	public void initDecoderMap() {

		decoderMap.put("0", "D");
		decoderMap.put("1", "A");
		decoderMap.put("2", "5");
		decoderMap.put("3", "1");
		decoderMap.put("4", "9");
		decoderMap.put("5", "E");
		decoderMap.put("6", "6");
		decoderMap.put("7", "2");
		decoderMap.put("8", "F");
		decoderMap.put("9", "8");
		decoderMap.put("A", "4");
		decoderMap.put("B", "0");
		decoderMap.put("C", "B");
		decoderMap.put("D", "C");
		decoderMap.put("E", "7");
		decoderMap.put("F", "3");
		
	}

	public String decryptTest(String encryptedMsg) {
		initDecoderMap();
		return decrypt(encryptedMsg);
	}



	
}
